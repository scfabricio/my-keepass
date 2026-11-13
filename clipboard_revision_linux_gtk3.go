//go:build linux && cgo && gtk3 && !android && !server

package main

/*
#cgo pkg-config: gtk+-3.0
#include <gtk/gtk.h>
#include <stdint.h>

static uintptr_t meuCofreClipboardRevision(void) {
	GtkClipboard *clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
	GObject *owner = gtk_clipboard_get_owner(clipboard);
	if (owner == NULL) return 0;
	g_object_ref(owner);
	return (uintptr_t)owner;
}

static int meuCofreClipboardRevisionMatches(uintptr_t revision) {
	GtkClipboard *clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
	return (uintptr_t)gtk_clipboard_get_owner(clipboard) == revision;
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
