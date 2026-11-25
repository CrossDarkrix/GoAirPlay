package main

// Stage 5: live audio playback on Windows via winmm waveOut.
// Pure Go (syscall lazy DLL), so the CGO_ENABLED=0 cross-compile keeps
// working. A small pool of waveOut buffers is fed from an accumulator
// that receives decoded PCM from the RTP data path. Volume arrives as
// SET_PARAMETER "volume: <dB>" and is applied as a linear gain while
// filling buffers.

import (
	"log"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	winmmDLL                 = syscall.NewLazyDLL("winmm.dll")
	procWaveOutOpen          = winmmDLL.NewProc("waveOutOpen")
	procWaveOutPrepareHeader = winmmDLL.NewProc("waveOutPrepareHeader")
	procWaveOutWrite         = winmmDLL.NewProc("waveOutWrite")
	procWaveOutUnprepare     = winmmDLL.NewProc("waveOutUnprepareHeader")
	procWaveOutReset         = winmmDLL.NewProc("waveOutReset")
	procWaveOutClose         = winmmDLL.NewProc("waveOutClose")
)

type waveFormatEx struct {
	FormatTag      uint16
	Channels       uint16
	SamplesPerSec  uint32
	AvgBytesPerSec uint32
	BlockAlign     uint16
	BitsPerSample  uint16
	Size           uint16
}

type waveHdr struct {
	Data          *byte
	BufferLength  uint32
	BytesRecorded uint32
	User          uintptr
	Flags         uint32
	Loops         uint32
	Next          *waveHdr
	Reserved      uintptr
}

const (
	waveMapper   = 0xFFFFFFFF
	whdrDone     = 0x00000001
	playBufCount = 16
	playBufSize  = 8192 // 2048 stereo frames @44.1kHz, ~46 ms
)

type winPlayer struct {
	mu     sync.Mutex
	hwo    uintptr
	hdrs   [playBufCount]*waveHdr
	bufs   [playBufCount][]byte
	busy   [playBufCount]bool
	acc    []byte
	feeder bool
}

var player = &winPlayer{}

func (p *winPlayer) openLocked() bool {
	if p.hwo != 0 {
		return true
	}
	fx := waveFormatEx{
		FormatTag:      1, // WAVE_FORMAT_PCM
		Channels:       2,
		SamplesPerSec:  44100,
		AvgBytesPerSec: 44100 * 4,
		BlockAlign:     4,
		BitsPerSample:  16,
		Size:           0,
	}
	var hwo uintptr
	r, _, _ := procWaveOutOpen.Call(
		uintptr(unsafe.Pointer(&hwo)),
		uintptr(waveMapper),
		uintptr(unsafe.Pointer(&fx)),
		0, 0, 0,
	)
	if r != 0 {
		log.Printf("[play] waveOutOpen failed: %d", r)
		return false
	}
	p.hwo = hwo
	for i := 0; i < playBufCount; i++ {
		p.bufs[i] = make([]byte, playBufSize)
		p.hdrs[i] = &waveHdr{}
		p.busy[i] = false
	}
	log.Printf("[play] waveOut opened (44.1kHz/16bit/stereo)")
	if !p.feeder {
		p.feeder = true
		go p.feedLoop()
	}
	return true
}

// enqueuePCM queues decoded PCM (44.1kHz, 16-bit, stereo) for playback.
func enqueuePCM(pcm []byte) {
	p := player
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.openLocked() {
		return
	}
	p.acc = append(p.acc, pcm...)
	if len(p.acc) > playMaxAcc {
		drop := len(p.acc) - playMaxAcc
		drop -= drop % 4
		p.acc = append([]byte(nil), p.acc[drop:]...)
	}
}

func (p *winPlayer) feedLoop() {
	for {
		time.Sleep(4 * time.Millisecond)
		p.mu.Lock()
		if p.hwo == 0 {
			p.mu.Unlock()
			continue
		}
		// reap finished buffers
		for i := 0; i < playBufCount; i++ {
			if p.busy[i] && p.hdrs[i].Flags&whdrDone != 0 {
				procWaveOutUnprepare.Call(p.hwo, uintptr(unsafe.Pointer(p.hdrs[i])), unsafe.Sizeof(waveHdr{}))
				p.busy[i] = false
			}
		}
		// feed full buffers
		g := currentGain()
		for len(p.acc) >= playBufSize {
			slot := -1
			for i := 0; i < playBufCount; i++ {
				if !p.busy[i] {
					slot = i
					break
				}
			}
			if slot < 0 {
				break
			}
			buf := p.bufs[slot]
			scalePCM(buf, p.acc[:playBufSize], g)
			p.acc = p.acc[playBufSize:]
			hdr := p.hdrs[slot]
			hdr.Data = &buf[0]
			hdr.BufferLength = playBufSize
			hdr.BytesRecorded = 0
			hdr.Flags = 0
			hdr.Loops = 0
			if r, _, _ := procWaveOutPrepareHeader.Call(p.hwo, uintptr(unsafe.Pointer(hdr)), unsafe.Sizeof(waveHdr{})); r != 0 {
				log.Printf("[play] waveOutPrepareHeader failed: %d", r)
				break
			}
			if r, _, _ := procWaveOutWrite.Call(p.hwo, uintptr(unsafe.Pointer(hdr)), unsafe.Sizeof(waveHdr{})); r != 0 {
				log.Printf("[play] waveOutWrite failed: %d", r)
				procWaveOutUnprepare.Call(p.hwo, uintptr(unsafe.Pointer(hdr)), unsafe.Sizeof(waveHdr{}))
				break
			}
			p.busy[slot] = true
		}
		p.mu.Unlock()
	}
}

// stopPlayback resets and closes the waveOut device (on TEARDOWN).
func stopPlayback() {
	p := player
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hwo == 0 {
		return
	}
	procWaveOutReset.Call(p.hwo)
	for i := 0; i < playBufCount; i++ {
		if p.busy[i] {
			procWaveOutUnprepare.Call(p.hwo, uintptr(unsafe.Pointer(p.hdrs[i])), unsafe.Sizeof(waveHdr{}))
			p.busy[i] = false
		}
	}
	procWaveOutClose.Call(p.hwo)
	p.hwo = 0
	p.acc = nil
	log.Printf("[play] waveOut closed")
}
