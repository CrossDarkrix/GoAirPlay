//go:build !windows && !linux && !android && !ios && !darwin

package main

// Playback is not implemented on this platform; these stubs keep
// other builds (unit tests on the dev VM) compiling.

func enqueuePCM(pcm []byte) {}
func stopPlayback()         {}
