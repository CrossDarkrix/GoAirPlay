//go:build linux || android

package main

// Audio output on Linux/Android (incl. Termux): decoded PCM is piped
// to an external player process's stdin. Backends are tried in order:
// ffplay (ffmpeg), mpv, paplay (PulseAudio). If none is installed the
// audio is dropped with a one-time hint in the log.

import (
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

type pipePlayer struct {
	mu         sync.Mutex
	acc        []byte
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	started    bool
	dead       bool
	hinted     bool
	stdoutMode bool
}

var ppipe = &pipePlayer{}

func (p *pipePlayer) startLocked() bool {
	if p.stdoutMode {
		return true
	}
	if p.cmd != nil {
		return true
	}
	if p.dead {
		return false
	}
	if *pcmStdout {
		// The Android app shell reads our stdout as the PCM stream.
		p.stdoutMode = true
		log.Printf("[play] audio output to stdout (PCM s16le 44.1kHz stereo)")
		return true
	}
	type backend struct {
		name string
		args []string
	}
	candidates := []backend{
		{"ffplay", []string{"-hide_banner", "-loglevel", "error", "-nodisp", "-autoexit",
			"-fflags", "nobuffer", "-flags", "low_delay", "-probesize", "32", "-analyzeduration", "0",
			"-f", "s16le", "-ar", "44100", "-ac", "2", "-i", "-"}},
		{"mpv", []string{"--no-video", "--really-quiet", "--demuxer=rawaudio",
			"--demuxer-rawaudio-format=s16le", "--demuxer-rawaudio-rate=44100",
			"--demuxer-rawaudio-channels=2", "-"}},
		{"paplay", []string{"--raw", "--format=s16le", "--rate=44100", "--channels=2"}},
	}
	for _, b := range candidates {
		path, err := exec.LookPath(b.name)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, b.args...)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			continue
		}
		if err := cmd.Start(); err != nil {
			continue
		}
		p.cmd = cmd
		p.stdin = stdin
		log.Printf("[play] audio output via %s", b.name)
		return true
	}
	if !p.hinted {
		p.hinted = true
		log.Printf("[play] no audio player found - install ffmpeg (ffplay) or mpv in Termux to hear sound")
	}
	p.dead = true
	return false
}

func enqueuePCM(pcm []byte) {
	p := ppipe
	p.mu.Lock()
	if !p.started {
		p.started = true
		go p.writerLoop()
	}
	if !p.startLocked() {
		p.mu.Unlock()
		return
	}
	p.acc = append(p.acc, pcm...)
	if len(p.acc) > playMaxAcc {
		drop := len(p.acc) - playMaxAcc
		drop -= drop % 4
		p.acc = append([]byte(nil), p.acc[drop:]...)
	}
	p.mu.Unlock()
}

func (p *pipePlayer) writerLoop() {
	tmp := make([]byte, 32768)
	for {
		time.Sleep(5 * time.Millisecond)
		p.mu.Lock()
		if (p.cmd == nil && !p.stdoutMode) || len(p.acc) == 0 {
			p.mu.Unlock()
			continue
		}
		n := len(p.acc)
		if n > len(tmp) {
			n = len(tmp)
		}
		scalePCM(tmp[:n], p.acc[:n], currentGain())
		p.acc = p.acc[n:]
		stdin := p.stdin
		stdoutMode := p.stdoutMode
		p.mu.Unlock()
		var err error
		if stdoutMode {
			_, err = os.Stdout.Write(tmp[:n])
		} else {
			_, err = stdin.Write(tmp[:n])
		}
		if err != nil {
			p.mu.Lock()
			if p.cmd != nil {
				p.cmd.Process.Kill()
				p.cmd = nil
				p.stdin = nil
				p.dead = true
				log.Printf("[play] player exited: %v", err)
			}
			p.mu.Unlock()
		}
	}
}

func stopPlayback() {
	p := ppipe
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stdoutMode {
		p.acc = nil
		return
	}
	if p.cmd != nil {
		p.stdin.Close()
		p.cmd.Process.Kill()
		p.cmd = nil
		p.stdin = nil
		log.Printf("[play] player stopped")
	}
	p.acc = nil
	p.dead = false
}
