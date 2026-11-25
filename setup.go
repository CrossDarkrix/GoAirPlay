package main

// SETUP handling, NTP timing responder, RTP receiver.
// SETUP 1 carries ekey/eiv: the stream AES key is playfair-decrypted and
// then hashed with the pair-verify ECDH secret (SHA-512, first 16 bytes).
// SETUP 2 carries the stream list: type 96 = audio. We answer with our
// UDP ports and start the timing/data/control listeners.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/maghul/go.alac"
	"howett.net/plist"
)

const (
	udpTimingPort  = 6002
	udpControlPort = 6001
	udpDataPort    = 6000
	ntpEpochOffset = 2208988800 // seconds between 1900 and 1970
)

type streamState struct {
	aesKey   []byte
	aesIV    []byte
	dataPkts atomic.Int64
	ct       uint64
	spf      uint64
	dec      *alac.Alac
	decErrs  atomic.Int64
	wav      *os.File
	wavBytes int64
	peak     int32
}

var curStream atomic.Pointer[streamState]

func ntpNow() (sec uint32, frac uint32) {
	now := time.Now()
	s := uint64(now.Unix()) + ntpEpochOffset
	f := uint64(now.Nanosecond()) * (1 << 32) / 1e9
	return uint32(s), uint32(f)
}

func (s *session) handleSETUP(headers map[string]string, body []byte) ([]byte, string) {
	var req map[string]interface{}
	if _, err := plist.Unmarshal(body, &req); err != nil {
		log.Printf("[setup] plist parse failed: %v", err)
		return nil, "400 Bad Request"
	}

	resp := map[string]interface{}{}
	st := &streamState{}

	// ---- SETUP 1: keys + timing ----
	if ekeyRaw, ok := req["ekey"].([]byte); ok {
		eivRaw, _ := req["eiv"].([]byte)
		if len(ekeyRaw) != 72 || len(eivRaw) != 16 {
			log.Printf("[setup] bad ekey/eiv lengths %d/%d", len(ekeyRaw), len(eivRaw))
			return nil, "400 Bad Request"
		}
		if len(s.fpKeymsg) != 164 {
			log.Printf("[setup] no FairPlay key message stored")
			return nil, "400 Bad Request"
		}
		pfKey := playfairDecrypt(s.fpKeymsg, ekeyRaw)
		if len(s.ecdhSecret) == 32 {
			// AirPlay 2 legacy protocol: the actual stream key is
			// SHA-512(playfair key || pair-verify ECDH secret), first 16 bytes.
			h := sha512.Sum512(append(append([]byte{}, pfKey...), s.ecdhSecret...))
			st.aesKey = append([]byte(nil), h[:16]...)
		} else {
			// Old protocol clients (no pairing): playfair key used directly.
			st.aesKey = pfKey
		}
		log.Printf("[setup] stream key ready")
		st.aesIV = append([]byte(nil), eivRaw...)
		curStream.Store(st)
		resp["timingPort"] = uint64(udpTimingPort)
		resp["eventPort"] = uint64(0)
		go runTimingServer()
		if tp, ok := req["timingPort"].(uint64); ok {
			log.Printf("[setup] client timingPort=%d timingProtocol=%v", tp, req["timingProtocol"])
		}
	}

	// ---- SETUP 2: streams ----
	if streamsRaw, ok := req["streams"].([]interface{}); ok {
		var resStreams []interface{}
		for _, si := range streamsRaw {
			sm, _ := si.(map[string]interface{})
			typ, _ := sm["type"].(uint64)
			log.Printf("[setup] stream type=%d ct=%v spf=%v audioFormat=%v", typ, sm["ct"], sm["spf"], sm["audioFormat"])
			switch typ {
			case 96: // audio
				if cur := curStream.Load(); cur != nil {
					ctv, _ := sm["ct"].(uint64)
					spfv, _ := sm["spf"].(uint64)
					cur.ct = ctv
					cur.spf = spfv
					if ctv == 2 {
						var dec *alac.Alac
						var err error
						if spfv == 352 {
							dec, err = alac.New()
						} else {
							dec, err = alac.NewFromFmtp(fmt.Sprintf("96 %d 0 16 40 10 14 2 255 0 0 44100", spfv))
						}
						if err == nil {
							cur.dec = dec
							log.Printf("[setup] ALAC decoder ready (spf=%d)", spfv)
						} else {
							log.Printf("[setup] ALAC decoder failed: %v", err)
						}
					} else {
						log.Printf("[setup] stream ct=%d is not ALAC - decode skipped for now", ctv)
					}
				}
				resStreams = append(resStreams, map[string]interface{}{
					"type":        uint64(96),
					"dataPort":    uint64(udpDataPort),
					"controlPort": uint64(udpControlPort),
				})
				go runDataServer()
				go runControlServer()
			case 110: // mirroring (accepted, not decoded yet)
				resStreams = append(resStreams, map[string]interface{}{
					"type":     uint64(110),
					"dataPort": uint64(udpDataPort + 10),
				})
			}
		}
		if len(resStreams) > 0 {
			resp["streams"] = resStreams
		}
	}

	out, err := plist.Marshal(resp, plist.BinaryFormat)
	if err != nil {
		log.Printf("[setup] response marshal failed: %v", err)
		return nil, "500 Internal Server Error"
	}
	log.Printf("[setup] responding %d bytes: %v", len(out), resp)
	return out, "200 OK"
}

// ---- NTP timing server ----

var timingStarted atomic.Bool

func runTimingServer() {
	if !timingStarted.CompareAndSwap(false, true) {
		return
	}
	addr, err := net.ResolveUDPAddr("udp", ":6002")
	if err != nil {
		log.Printf("[ntp] resolve: %v", err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("[ntp] listen: %v", err)
		return
	}
	log.Printf("[ntp] timing server on :%d", udpTimingPort)
	buf := make([]byte, 64)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 32 {
			continue
		}
		recvSec, recvFrac := ntpNow()
		var res [32]byte
		copy(res[:], buf[:n])
		res[0] = 0x80
		res[1] = 0xd3 // timing response
		// origin = client's transmit timestamp (request bytes 24..31)
		copy(res[8:16], buf[24:32])
		binary.BigEndian.PutUint32(res[16:20], recvSec)
		binary.BigEndian.PutUint32(res[20:24], recvFrac)
		sendSec, sendFrac := ntpNow()
		binary.BigEndian.PutUint32(res[24:28], sendSec)
		binary.BigEndian.PutUint32(res[28:32], sendFrac)
		conn.WriteToUDP(res[:], src)
	}
}

// ---- RTP data server (decrypt + ALAC decode + playback) ----

var dataStarted atomic.Bool

func runDataServer() {
	if !dataStarted.CompareAndSwap(false, true) {
		return
	}
	caddr, _ := net.ResolveUDPAddr("udp", ":6000")
	conn, err := net.ListenUDP("udp", caddr)
	if err != nil {
		log.Printf("[rtp] listen: %v", err)
		return
	}
	log.Printf("[rtp] data server on :%d", udpDataPort)
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		st := curStream.Load()
		if st == nil {
			continue
		}
		pkt := st.dataPkts.Add(1)
		if n <= 12 {
			continue
		}
		payload := buf[12:n]
		plain := decryptRAOP(st.aesKey, st.aesIV, payload)
		if st.dec != nil {
			pcm := safeDecode(st, plain)
			if len(pcm) > 0 {
				enqueuePCM(pcm)
				st.writeWAV(pcm)
				for i := 0; i+1 < len(pcm); i += 2 {
					v := int32(int16(binary.LittleEndian.Uint16(pcm[i:])))
					if v < 0 {
						v = -v
					}
					if v > st.peak {
						st.peak = v
					}
				}
			}
		}
		if pkt%500 == 0 {
			log.Printf("[rtp] %d packets, peak=%d, decode errors=%d", pkt, st.peak, st.decErrs.Load())
			st.peak = 0
		}
	}
}

// decryptRAOP decrypts an RAOP audio payload: AES-CBC over full 16-byte
// blocks; the trailing partial block (if any) is left as-is.
func decryptRAOP(key, iv, payload []byte) []byte {
	out := append([]byte(nil), payload...)
	blocks := len(payload) / 16
	if blocks == 0 {
		return out
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return out
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out[:blocks*16], payload[:blocks*16])
	return out
}

// ---- control server (sync packets; log first few) ----

var controlStarted atomic.Bool

func runControlServer() {
	if !controlStarted.CompareAndSwap(false, true) {
		return
	}
	caddr, _ := net.ResolveUDPAddr("udp", ":6001")
	conn, err := net.ListenUDP("udp", caddr)
	if err != nil {
		log.Printf("[ctrl] listen: %v", err)
		return
	}
	log.Printf("[ctrl] control server on :%d", udpControlPort)
	buf := make([]byte, 1024)
	var count int64
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		count++
		if count <= 3 {
			log.Printf("[ctrl] pkt #%d len=%d first bytes: %x", count, n, buf[:min(20, n)])
		}
	}
}


func safeDecode(st *streamState, frame []byte) (pcm []byte) {
	defer func() {
		if r := recover(); r != nil {
			if st.decErrs.Add(1) <= 3 {
				log.Printf("[alac] decode panic: %v", r)
			}
			pcm = nil
		}
	}()
	return st.dec.Decode(frame)
}

// writeWAV appends PCM to goairplay_out.wav next to the executable
// when started with -record, creating it with a streaming header
// on first use. It is a debug aid and off by default.
func (st *streamState) writeWAV(pcm []byte) {
	if !*recordWAV {
		return
	}
	if st.wav == nil {
		exe, _ := os.Executable()
		path := filepath.Join(filepath.Dir(exe), "goairplay_out.wav")
		f, err := os.Create(path)
		if err != nil {
			log.Printf("[wav] create failed: %v", err)
			return
		}
		hdr := make([]byte, 44)
		copy(hdr[0:], "RIFF")
		binary.LittleEndian.PutUint32(hdr[4:], 0xFFFFFFF0)
		copy(hdr[8:], "WAVEfmt ")
		binary.LittleEndian.PutUint32(hdr[16:], 16)
		binary.LittleEndian.PutUint16(hdr[20:], 1) // PCM
		binary.LittleEndian.PutUint16(hdr[22:], 2) // stereo
		binary.LittleEndian.PutUint32(hdr[24:], 44100)
		binary.LittleEndian.PutUint32(hdr[28:], 44100*4)
		binary.LittleEndian.PutUint16(hdr[32:], 4)
		binary.LittleEndian.PutUint16(hdr[34:], 16)
		copy(hdr[36:], "data")
		binary.LittleEndian.PutUint32(hdr[40:], 0xFFFFFFF0)
		f.Write(hdr)
		st.wav = f
		log.Printf("[wav] recording decoded audio to %s", path)
	}
	st.wav.Write(pcm)
	st.wavBytes += int64(len(pcm))
}
