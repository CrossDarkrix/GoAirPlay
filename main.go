// GoAirPlay - AirPlay (RAOP) audio receiver written in Go.
// Stage 2: discovery (stage 1) + GET /info + pair-setup / pair-verify.
// Protocol facts were learned by reading the UxPlay (GPLv3) sources;
// this implementation is original Go code written from the protocol behavior.
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/grandcat/zeroconf"
	"howett.net/plist"
)

// buildStamp identifies the build in the startup banner, so a stale
// binary on a device can never be mistaken for the latest one.
const buildStamp = "1.0.1"

var (
	deviceName = flag.String("name", "GoAirPlay", "receiver name shown on the iPhone AirPlay list")
	rtspPort   = flag.Int("port", 7000, "RTSP listen port")
	recordWAV  = flag.Bool("record", false, "also record decoded audio to goairplay_out.wav (debug)")
	browseMode = flag.Bool("browse", false, "diagnostic: list AirPlay receivers visible via mDNS for 6 seconds, then exit")
	dataDir    = flag.String("data-dir", "", "directory for the identity key file (default: next to the executable)")
	pcmStdout  = flag.Bool("pcm-stdout", false, "write decoded PCM to stdout instead of a local player (used by the Android app shell)")
)

// receiver identity (persistent Ed25519 keypair)
var (
	edPub  ed25519.PublicKey
	edPriv ed25519.PrivateKey
	devMAC string // "d8:cb:8a:cc:01:f9"
	devIP  string
)

var raopTXT []string
var airplayTXT []string

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)

	if *browseMode {
		runBrowse()
		return
	}

	iface, mac, lanIP := pickLANInterface()
	devMAC, devIP = mac, lanIP
	loadIdentity()
	if devMAC == "" || devMAC == "02:00:00:00:00:00" {
		// No usable MAC (Android hides it, iOS reports the dummy
		// 02:00:00:00:00:00): derive a stable, locally-administered
		// device ID from our Ed25519 identity.
		b := append([]byte(nil), edPub[:6]...)
		b[0] = (b[0] & 0xFE) | 0x02
		devMAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
		log.Printf("no hardware MAC available - derived device ID %s from identity key", devMAC)
	}

	raopTXT = []string{
		"txtvers=1",
		"ch=2",
		"cn=0,1,2,3",
		"da=true",
		"et=0,3,5",
		"md=0,1,2",
		"pw=false",
		"sr=44100",
		"ss=16",
		"tp=UDP",
		"vn=65537",
		"vs=220.68",
		"am=AppleTV3,2",
		"sf=0x4",
	}
	airplayTXT = []string{
		"deviceid=" + devMAC,
		"features=0x5A7FFFF7,0x1E",
		"flags=0x4",
		"model=AppleTV3,2",
		"pw=false",
		"srcvers=220.68",
		"vv=2",
	}

	bannerW := io.Writer(os.Stdout)
	if *pcmStdout {
		bannerW = os.Stderr // stdout is reserved for the PCM stream
	}
	fmt.Fprintln(bannerW, "######################")
	fmt.Fprintf(bannerW, "# GoAirPlay - AirPlay audio receiver (build %s)\n", buildStamp)
	fmt.Fprintf(bannerW, "# Receiver name : %s\n", *deviceName)
	fmt.Fprintf(bannerW, "# RTSP port     : %d\n", *rtspPort)
	fmt.Fprintf(bannerW, "# LAN interface : %s (%s, MAC %s)\n", iface.Name, devIP, devMAC)
	fmt.Fprintln(bannerW, "######################")

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *rtspPort))
	if err != nil {
		log.Fatalf("RTSP listen failed: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(conn)
		}
	}()
	log.Printf("RTSP server listening on :%d", *rtspPort)

	var ifaces []net.Interface
	if iface.Name != "" {
		ifaces = []net.Interface{iface}
	}
	macHex := strings.ReplaceAll(devMAC, ":", "")
	raopInstance := fmt.Sprintf("%s@%s", macHex, *deviceName)
	register := func(instance, service string, txt []string) *zeroconf.Server {
		if os.Getenv("GOAIRPLAY_MINI") == "1" {
			return nil // diagnostics: force the built-in publisher
		}
		// With a known LAN IP, RegisterProxy pins the advertisement to
		// it; the plain Register path asks the library to guess the
		// host addresses, which fails on Android/Termux.
		if devIP != "" {
			if srv, err := zeroconf.RegisterProxy(instance, service, "local.", *rtspPort, *deviceName, []string{devIP}, txt, ifaces); err == nil {
				return srv
			} else {
				log.Printf("mDNS RegisterProxy (%s) failed: %v - falling back", service, err)
			}
		}
		srv, err := zeroconf.Register(instance, service, "local.", *rtspPort, txt, ifaces)
		if err != nil {
			log.Printf("mDNS register (%s) failed: %v", service, err)
			return nil
		}
		return srv
	}
	raopServer := register(raopInstance, "_raop._tcp", raopTXT)
	airplayServer := register(*deviceName, "_airplay._tcp", airplayTXT)
	var mini *miniMDNS
	if raopServer == nil && airplayServer == nil {
		// Last resort: the built-in publisher, which needs only the
		// LAN IP (no interface enumeration at all).
		var err error
		mini, err = startMiniMDNS(devIP, *rtspPort, *deviceName, []mdnsSvc{
			{service: "_raop._tcp.local", instance: raopInstance + "._raop._tcp.local", txt: raopTXT},
			{service: "_airplay._tcp.local", instance: *deviceName + "._airplay._tcp.local", txt: airplayTXT},
		})
		if err != nil {
			log.Fatalf("mDNS fallback also failed: %v", err)
		}
	} else {
		log.Printf("mDNS advertising as %q on %s", *deviceName, devIP)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down...")
	if raopServer != nil {
		raopServer.Shutdown()
	}
	if airplayServer != nil {
		airplayServer.Shutdown()
	}
	if mini != nil {
		mini.Shutdown()
	}
	ln.Close()
}

// loadIdentity loads the persistent Ed25519 seed from next to the executable,
// generating and saving it on first run.
func loadIdentity() {
	dir := *dataDir
	if dir == "" {
		exe, _ := os.Executable()
		dir = filepath.Dir(exe)
	}
	path := filepath.Join(dir, "goairplay_key.bin")
	seed, err := os.ReadFile(path)
	if err == nil && len(seed) == ed25519.SeedSize {
		edPriv = ed25519.NewKeyFromSeed(seed)
	} else {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("ed25519 generate: %v", err)
		}
		edPriv = priv
		if err := os.WriteFile(path, priv.Seed(), 0600); err != nil {
			log.Printf("warning: could not save identity key: %v", err)
		} else {
			log.Printf("generated receiver identity key: %s", path)
		}
	}
	edPub = edPriv.Public().(ed25519.PublicKey)
}

// ---------- per-connection session ----------

type session struct {
	clientEdPub []byte // from pair-setup
	ecdhPriv    *ecdh.PrivateKey
	ecdhSecret  []byte
	peerEcdh    []byte
	handshake   bool
	verified    bool
	fpVersion   int
	fpKeymsg    []byte
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("[conn] from %s", remote)
	sess := &session{}
	reader := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		reqLine, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[conn] read error from %s: %v", remote, err)
			}
			return
		}
		reqLine = strings.TrimSpace(reqLine)
		if reqLine == "" {
			continue
		}
		parts := strings.SplitN(reqLine, " ", 3)
		if len(parts) < 3 {
			log.Printf("[conn] malformed request line: %q", reqLine)
			return
		}
		method, uri := parts[0], parts[1]

		headers := map[string]string{}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			if k, v, ok := strings.Cut(line, ":"); ok {
				headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		var body []byte
		if cl, ok := headers["Content-Length"]; ok {
			if n, err := strconv.Atoi(cl); err == nil && n > 0 && n <= 1<<20 {
				body = make([]byte, n)
				if _, err := io.ReadFull(reader, body); err != nil {
					log.Printf("[conn] body read error: %v", err)
					return
				}
			}
		}

		log.Printf("[conn] %s %s CSeq=%s len=%d", method, uri, headers["CSeq"], len(body))

		status, extra, respBody, contentType := sess.dispatch(method, uri, headers, body)
		var resp strings.Builder
		fmt.Fprintf(&resp, "RTSP/1.0 %s\r\n", status)
		if cseq, ok := headers["CSeq"]; ok {
			resp.WriteString("CSeq: " + cseq + "\r\n")
		}
		resp.WriteString("Server: GoAirPlay/0.3\r\n")
		for _, h := range extra {
			resp.WriteString(h + "\r\n")
		}
		if contentType != "" {
			resp.WriteString("Content-Type: " + contentType + "\r\n")
		}
		if respBody != nil {
			fmt.Fprintf(&resp, "Content-Length: %d\r\n", len(respBody))
		}
		resp.WriteString("\r\n")
		if _, err := conn.Write([]byte(resp.String())); err != nil {
			return
		}
		if respBody != nil {
			if _, err := conn.Write(respBody); err != nil {
				return
			}
		}
	}
}

func (s *session) dispatch(method, uri string, headers map[string]string, body []byte) (status string, extra []string, respBody []byte, contentType string) {
	switch {
	case method == "GET" && uri == "/info":
		b := buildInfoResponse(body)
		log.Printf("[info] responding %d bytes", len(b))
		return "200 OK", nil, b, "application/x-apple-binary-plist"
	case method == "POST" && uri == "/pair-setup":
		if len(body) != 32 {
			log.Printf("[pair-setup] unexpected body length %d", len(body))
			return "400 Bad Request", nil, nil, ""
		}
		s.clientEdPub = append([]byte(nil), body...)
		log.Printf("[pair-setup] got client Ed25519 pk, returning ours")
		return "200 OK", nil, []byte(edPub), "application/octet-stream"
	case method == "POST" && uri == "/pair-verify":
		b, ok := s.pairVerify(body)
		if !ok {
			return "400 Bad Request", nil, nil, ""
		}
		return "200 OK", nil, b, "application/octet-stream"
	case method == "POST" && uri == "/fp-setup":
		b := s.fpSetup(body)
		if b == nil {
			return "400 Bad Request", nil, nil, ""
		}
		return "200 OK", nil, b, "application/octet-stream"
	case method == "SETUP":
		b, status := s.handleSETUP(headers, body)
		if b == nil {
			return status, nil, nil, ""
		}
		return status, nil, b, "application/x-apple-binary-plist"
	case method == "OPTIONS":
		return "200 OK", []string{"Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER"}, nil, ""
	case method == "SET_PARAMETER" && strings.HasPrefix(string(body), "volume:"):
		v := strings.TrimSpace(strings.TrimPrefix(string(body), "volume:"))
		if db, err := strconv.ParseFloat(v, 64); err == nil {
			setVolumeDB(db)
			log.Printf("[conn] volume set to %.2f dB", db)
		}
		return "200 OK", nil, nil, ""
	case method == "TEARDOWN":
		stopPlayback()
		log.Printf("[conn] TEARDOWN - playback stopped")
		return "200 OK", nil, nil, ""
	default:
		log.Printf("[conn] unhandled %s %s - answering 200 empty", method, uri)
		if len(body) > 0 {
			log.Printf("[conn]   body %d bytes: %q", len(body), body[:min(len(body), 200)])
		}
		return "200 OK", nil, nil, ""
	}
}

// pairVerify implements the two-step AirPlay pair-verify handshake.
func (s *session) pairVerify(body []byte) ([]byte, bool) {
	if len(body) < 4 {
		log.Printf("[pair-verify] body too short: %d", len(body))
		return nil, false
	}
	switch body[0] {
	case 1:
		if len(body) != 4+32+32 {
			log.Printf("[pair-verify] step1 bad length %d", len(body))
			return nil, false
		}
		theirEcdh := body[4 : 4+32]
		theirEd := body[4+32 : 4+64]
		s.peerEcdh = append([]byte(nil), theirEcdh...)
		if len(s.clientEdPub) == 0 {
			s.clientEdPub = append([]byte(nil), theirEd...)
		}
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, false
		}
		s.ecdhPriv = priv
		pub, err := ecdh.X25519().NewPublicKey(theirEcdh)
		if err != nil {
			return nil, false
		}
		secret, err := priv.ECDH(pub)
		if err != nil {
			return nil, false
		}
		s.ecdhSecret = secret
		s.handshake = true

		// signature = Ed25519_sign(our_ecdh_pk || their_ecdh_pk), AES-CTR encrypted
		msg := append(append([]byte{}, priv.PublicKey().Bytes()...), theirEcdh...)
		sig := ed25519.Sign(edPriv, msg)
		enc := aesCTR(s.ecdhSecret, sig)
		log.Printf("[pair-verify] step1 OK, returning our ecdh pk + encrypted signature")
		out := append(append([]byte{}, priv.PublicKey().Bytes()...), enc...)
		return out, true
	case 0:
		if len(body) != 4+64 {
			log.Printf("[pair-verify] step2 bad length %d", len(body))
			return nil, false
		}
		if !s.handshake {
			log.Printf("[pair-verify] step2 without step1")
			return nil, false
		}
		// decrypt: the client already consumed one 64-byte CTR block, so advance one block first
		key, iv := derivePairVerifyKeyIV(s.ecdhSecret)
		block, _ := aes.NewCipher(key)
		stream := cipher.NewCTR(block, iv)
		fake := make([]byte, 64)
		stream.XORKeyStream(fake, fake)
		sig := make([]byte, 64)
		stream.XORKeyStream(sig, body[4:4+64])
		// verify Ed25519 over (their_ecdh_pk || our_ecdh_pk) with their Ed key
		theirEcdh := s.ecdhPeerBytes()
		msg := append(append([]byte{}, theirEcdh...), s.ecdhPriv.PublicKey().Bytes()...)
		if !ed25519.Verify(ed25519.PublicKey(s.clientEdPub), msg, sig) {
			log.Printf("[pair-verify] step2 signature INVALID")
			return nil, false
		}
		s.verified = true
		log.Printf("[pair-verify] step2 OK - client verified!")
		return []byte{}, true
	}
	log.Printf("[pair-verify] unknown step byte %d", body[0])
	return nil, false
}

// ecdhPeerBytes recomputes the peer public key bytes from the stored secret's session.
// We stored only the secret, so keep the peer key in the session too.
func (s *session) ecdhPeerBytes() []byte { return s.peerEcdh }

func derivePairVerifyKeyIV(secret []byte) (key, iv []byte) {
	h1 := sha512.Sum512(append([]byte("Pair-Verify-AES-Key"), secret...))
	h2 := sha512.Sum512(append([]byte("Pair-Verify-AES-IV"), secret...))
	return h1[:16], h2[:16]
}

func aesCTR(secret, data []byte) []byte {
	key, iv := derivePairVerifyKeyIV(secret)
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(data))
	cipher.NewCTR(block, iv).XORKeyStream(out, data)
	return out
}

// ---------- /info ----------

func txtWire(txt []string) []byte {
	var out []byte
	for _, e := range txt {
		out = append(out, byte(len(e)))
		out = append(out, e...)
	}
	return out
}

func buildInfoResponse(reqBody []byte) []byte {
	// qualifier request? {"qualifier": ["txtAirPlay"|"txtRAOP"]}
	if len(reqBody) > 0 {
		var req map[string]interface{}
		if _, err := plist.Unmarshal(reqBody, &req); err == nil {
			if q, ok := req["qualifier"].([]interface{}); ok && len(q) > 0 {
				switch q[0] {
				case "txtAirPlay":
					out, _ := plist.Marshal(map[string]interface{}{"txtAirPlay": txtWire(airplayTXT)}, plist.BinaryFormat)
					return out
				case "txtRAOP":
					out, _ := plist.Marshal(map[string]interface{}{"txtRAOP": txtWire(raopTXT)}, plist.BinaryFormat)
					return out
				}
			}
		}
	}
	features := uint64(0x5A7FFFF7) | uint64(0x1E)<<32
	info := map[string]interface{}{
		"deviceID":                 devMAC,
		"macAddress":               devMAC,
		"pk":                       []byte(edPub),
		"features":                 features,
		"name":                     *deviceName,
		"pi":                       "2f1a4d2c-0000-4000-8000-000000000000",
		"vv":                       uint64(2),
		"statusFlags":              uint64(68),
		"keepAliveLowPower":        true,
		"sourceVersion":            "220.68",
		"keepAliveSendStatsAsBody": true,
		"model":                    "AppleTV3,2",
		"initialVolume":            float64(0),
		"audioLatencies": []interface{}{
			map[string]interface{}{"type": uint64(100), "audioType": "default", "inputLatencyMicros": uint64(0), "outputLatencyMicros": false},
			map[string]interface{}{"type": uint64(101), "audioType": "default", "inputLatencyMicros": uint64(0), "outputLatencyMicros": false},
		},
		"audioFormats": []interface{}{
			map[string]interface{}{"type": uint64(100), "audioInputFormats": uint64(0x3fffffc), "audioOutputFormats": uint64(0x3fffffc)},
			map[string]interface{}{"type": uint64(101), "audioInputFormats": uint64(0x3fffffc), "audioOutputFormats": uint64(0x3fffffc)},
		},
		"displays": []interface{}{
			map[string]interface{}{
				"uuid":          "e0ff8a27-6738-3d56-8a16-cc53aacee925",
				"width":         uint64(1920),
				"height":        uint64(1080),
				"widthPixels":   uint64(1920),
				"heightPixels":  uint64(1080),
				"widthPhysical": uint64(0),
				"heightPhysical": uint64(0),
				"rotation":      false,
				"refreshRate":   1.0 / 60.0,
				"maxFPS":        uint64(30),
				"overscanned":   false,
				"features":      uint64(14),
			},
		},
	}
	out, _ := plist.Marshal(info, plist.BinaryFormat)
	return out
}

// ---------- network helpers ----------

func pickLANInterface() (net.Interface, string, string) {
	type cand struct {
		iface net.Interface
		mac   string
		ip    string
		score int
	}
	var cands []cand
	var anyV4 []cand
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		mac := ""
		if len(ifc.HardwareAddr) == 6 {
			m := ifc.HardwareAddr.String()
			// Android reports a dummy MAC (02:00:00:00:00:00); treat
			// it and all-zero as "no MAC" so the caller derives one.
			if m != "02:00:00:00:00:00" && m != "00:00:00:00:00:00" {
				mac = m
			}
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil {
				continue
			}
			anyV4 = append(anyV4, cand{ifc, mac, ip.String(), 0})
			score := -1
			switch {
			case ip[0] == 192 && ip[1] == 168:
				score = 3
			case ip[0] == 10:
				score = 2
			case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
				score = 1
			}
			if score >= 0 {
				cands = append(cands, cand{ifc, mac, ip.String(), score})
			}
		}
	}
	pool := cands
	if len(pool) == 0 {
		pool = anyV4
	}
	if len(pool) == 0 {
		// No interface addresses are visible at all (Android/Termux
		// hides them from Go's enumeration). Hand back an interface
		// built from /sys/class/net as the mDNS join target, and
		// discover our LAN address from a UDP dial instead.
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagLoopback == 0 {
				return ifc, "", fallbackDialIP()
			}
		}
		if sys := sysfsInterfaces(); len(sys) > 0 {
			return sys[0], "", fallbackDialIP()
		}
		return net.Interface{}, "", fallbackDialIP()
	}
	best := pool[0]
	for _, c := range pool[1:] {
		if c.score > best.score {
			best = c
		}
	}
	return best.iface, best.mac, best.ip
}

// fallbackDialIP discovers the outward-facing local address by
// "dialing" UDP targets (no traffic is sent). Used where interface
// address enumeration is unavailable, e.g. Android/Termux.
func fallbackDialIP() string {
	for _, target := range []string{"8.8.8.8:80", "1.1.1.1:80", "192.168.0.1:80", "10.0.0.1:80", "172.16.0.1:80"} {
		conn, err := net.Dial("udp", target)
		if err != nil {
			continue
		}
		la, _ := conn.LocalAddr().(*net.UDPAddr)
		conn.Close()
		if la != nil && la.IP != nil && la.IP.To4() != nil && !la.IP.IsLoopback() && !la.IP.IsUnspecified() {
			return la.IP.String()
		}
	}
	return ""
}
