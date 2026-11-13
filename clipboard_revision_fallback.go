//go:build server || ios || android || (!darwin && !windows && (!linux || !cgo))

package main

func captureClipboardRevision() (uintptr, bool) { return 0, false }
func clipboardRevisionMatches(uintptr) bool     { return false }
func releaseClipboardRevision(uintptr)          {}
