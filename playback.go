package main

// Shared playback helpers: the AirPlay volume (SET_PARAMETER) kept as
// a linear gain, and a PCM scaler used by the platform backends.

import (
	"math"
	"sync/atomic"
)

// playMaxAcc caps the queued PCM (about 1.5 s of audio) so a stalled
// output drops old audio instead of growing latency without bound.
const playMaxAcc = 176400 * 3 / 2

var gainBits atomic.Uint64

func init() {
	gainBits.Store(math.Float64bits(1.0))
}

func currentGain() float64 {
	return math.Float64frombits(gainBits.Load())
}

// setVolumeDB converts an AirPlay volume (0 = full, -144 = mute) to gain.
func setVolumeDB(db float64) {
	if db <= -144 {
		gainBits.Store(math.Float64bits(0))
		return
	}
	if db > 0 {
		db = 0
	}
	gainBits.Store(math.Float64bits(math.Pow(10, db/20)))
}

// scalePCM copies src to dst applying the gain (both little-endian
// 16-bit PCM). With unity gain it is a plain copy.
func scalePCM(dst, src []byte, g float64) {
	if g == 1.0 {
		copy(dst, src)
		return
	}
	for j := 0; j+1 < len(src) && j+1 < len(dst); j += 2 {
		v := int16(uint16(src[j]) | uint16(src[j+1])<<8)
		f := float64(v) * g
		if f > 32767 {
			f = 32767
		} else if f < -32768 {
			f = -32768
		}
		s := uint16(int16(f))
		dst[j] = byte(s)
		dst[j+1] = byte(s >> 8)
	}
}
