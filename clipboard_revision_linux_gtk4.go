//go:build linux && cgo && !gtk3 && !android && !server

package main

/*
#cgo pkg-config: gtk4
#include <gtk/gtk.h>
#include <stdint.h>

static uintptr_t meuCofreClipboardRevision(void) {
	GdkDisplay *display = gdk_display_get_default();
	if (display == NULL) return 0;
	GdkClipboard *clipboard = gdk_display_get_clipboard(display);
	GdkContentProvider *content = gdk_clipboard_get_content(clipboard);
	if (content == NULL) return 0;
	g_object_ref(content);
	return (uintptr_t)content;
}

static int meuCofreClipboardRevisionMatches(uintptr_t revision) {
	GdkDisplay *display = gdk_display_get_default();
	if (display == NULL) return 0;
	GdkClipboard *clipboard = gdk_display_get_clipboard(display);
	return (uintptr_t)gdk_clipboard_get_content(clipboard) == revision;
}

static void meuCofreReleaseClipboardRevision(uintptr_t revision) {
	if (revision != 0) g_object_unref((gpointer)revision);
}
*/
import "C"

func captureClipboardRevision() (uintptr, bool) {
	revision := uintptr(C.meuCofreClipboardRevision())
	return revision, revision != 0
}

func clipboardRevisionMatches(revision uintptr) bool {
	return revision != 0 && C.meuCofreClipboardRevisionMatches(C.uintptr_t(revision)) != 0
}

func releaseClipboardRevision(revision uintptr) {
	if revision != 0 {
		C.meuCofreReleaseClipboardRevision(C.uintptr_t(revision))
	}
}
