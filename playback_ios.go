//go:build ios

package main

// Audio output on iOS (jailbroken devices): decoded PCM is played
// through AudioQueue Services (AudioToolbox) via cgo. iOS builds
// require cgo and external linking by design, so this backend only
// exists there. Buffers are filled from the same accumulator the
// other backends use, with the AirPlay volume applied as gain.

/*
#cgo LDFLAGS: -framework AudioToolbox -framework CoreFoundation

#include <AudioToolbox/AudioQueue.h>
#include <string.h>

extern int goFillPCM(void *dst, int maxlen);

static void aqCallback(void *userData, AudioQueueRef inAQ, AudioQueueBufferRef inBuffer) {
	int n = goFillPCM(inBuffer->mAudioData, (int)inBuffer->mAudioDataBytesCapacity);
	inBuffer->mAudioDataByteSize = (UInt32)n;
	AudioQueueEnqueueBuffer(inAQ, inBuffer, 0, NULL);
}

static AudioQueueRef aq = NULL;

static int aqStart(void) {
	if (aq != NULL) return 0;
	AudioStreamBasicDescription fmt;
	memset(&fmt, 0, sizeof(fmt));
	fmt.mSampleRate = 44100;
	fmt.mFormatID = kAudioFormatLinearPCM;
	fmt.mFormatFlags = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
	fmt.mBytesPerPacket = 4;
	fmt.mFramesPerPacket = 1;
	fmt.mBytesPerFrame = 4;
	fmt.mChannelsPerFrame = 2;
	fmt.mBitsPerChannel = 16;
	if (AudioQueueNewOutput(&fmt, aqCallback, NULL, NULL, NULL, 0, &aq) != noErr) return -1;
	for (int i = 0; i < 3; i++) {
		AudioQueueBufferRef buf;
		if (AudioQueueAllocateBuffer(aq, 8192, &buf) != noErr) return -1;
		aqCallback(NULL, aq, buf);
	}
	if (AudioQueueStart(aq, NULL) != noErr) return -1;
	return 0;
}

static void aqStop(void) {
	if (aq == NULL) return;
	AudioQueueStop(aq, true);
	AudioQueueDispose(aq, true);
	aq = NULL;
}
*/
import "C"

import (
	"log"
	"sync"
	"sync/atomic"
	"unsafe"
)

type iosPlayer struct {
	mu      sync.Mutex
	acc     []byte
	started bool
	dead    bool
}

var ipipe = &iosPlayer{}

var fillCalls atomic.Int64

//export goFillPCM
func goFillPCM(dst unsafe.Pointer, maxlen C.int) C.int {
	p := ipipe
	out := unsafe.Slice((*byte)(dst), int(maxlen))
	p.mu.Lock()
	n := len(p.acc)
	if n > int(maxlen) {
		n = int(maxlen)
	}
	n -= n % 4
	if n > 0 {
		scalePCM(out[:n], p.acc[:n], currentGain())
		p.acc = p.acc[n:]
	}
	p.mu.Unlock()
	if c := fillCalls.Add(1); c <= 5 {
		log.Printf("[play] AudioQueue fill #%d: %d bytes from accumulator", c, n)
	}
	if n == 0 {
		// Keep the queue fed with silence while the stream warms up.
		m := int(maxlen) - int(maxlen)%4
		for i := 0; i < m; i++ {
			out[i] = 0
		}
		return C.int(m)
	}
	return C.int(n)
}

func enqueuePCM(pcm []byte) {
	p := ipipe
	p.mu.Lock()
	if p.dead {
		p.mu.Unlock()
		return
	}
	starting := false
	if !p.started {
		// Claim the start before unlocking: aqStart primes its
		// buffers by calling goFillPCM, which takes this same
		// mutex, so aqStart must run WITHOUT the lock held.
		// (Holding it deadlocked the first enqueue: the priming
		// callback blocked on the mutex forever and the packet
		// reader stalled after exactly one packet.)
		p.started = true
		starting = true
	}
	p.acc = append(p.acc, pcm...)
	if len(p.acc) > playMaxAcc {
		drop := len(p.acc) - playMaxAcc
		drop -= drop % 4
		p.acc = append([]byte(nil), p.acc[drop:]...)
	}
	p.mu.Unlock()
	if starting {
		if C.aqStart() != 0 {
			p.mu.Lock()
			p.started = false
			p.dead = true
			p.mu.Unlock()
			log.Printf("[play] AudioQueue start failed - no audio output")
			return
		}
		log.Printf("[play] audio output via AudioQueue (iOS)")
	}
}

func stopPlayback() {
	p := ipipe
	p.mu.Lock()
	wasStarted := p.started
	p.started = false
	p.dead = false
	p.acc = nil
	p.mu.Unlock()
	if wasStarted {
		C.aqStop()
		log.Printf("[play] player stopped")
	}
}
