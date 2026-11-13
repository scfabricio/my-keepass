//go:build windows && !server

package main

import "syscall"

var clipboardUser32 = syscall.NewLazyDLL("user32.dll")
var getClipboardSequenceNumber = clipboardUser32.NewProc("GetClipboardSequenceNumber")

func captureClipboardRevision() (uintptr, bool) {
	sequence, _, _ := getClipboardSequenceNumber.Call()
	return uintptr(sequence), sequence != 0
}

func clipboardRevisionMatches(revision uintptr) bool {
	sequence, _, _ := getClipboardSequenceNumber.Call()
	return sequence != 0 && uintptr(sequence) == revision
}

func releaseClipboardRevision(uintptr) {}
