//go:build darwin && !server

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit
#import <AppKit/AppKit.h>
#include <stdint.h>

static uintptr_t meuCofreClipboardRevision(void) {
	return (uintptr_t)[[NSPasteboard generalPasteboard] changeCount];
}
*/
import "C"

func captureClipboardRevision() (uintptr, bool) {
	return uintptr(C.meuCofreClipboardRevision()), true
}

func clipboardRevisionMatches(revision uintptr) bool {
	return revision == uintptr(C.meuCofreClipboardRevision())
}

func releaseClipboardRevision(uintptr) {}
