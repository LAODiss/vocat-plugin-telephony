package recorder

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeStripsPathSeparators(t *testing.T) {
	// A caller-derived name must never be able to escape the directory.
	if got := Sanitize("../../etc/passwd"); strings.Contains(got, "/") || strings.Contains(got, "..") {
		t.Fatalf("Sanitize() = %q, still contains path syntax", got)
	}
	if got := Sanitize("20260901T120000Z-447700900123"); got != "20260901T120000Z-447700900123" {
		t.Fatalf("Sanitize() mangled a safe name: %q", got)
	}
	if Sanitize("") == "" {
		t.Fatal("an empty name must get a generated fallback")
	}
	if Sanitize("!!!") == "" {
		t.Fatal("an all-punctuation name must get a fallback, not an empty string")
	}
	if len(Sanitize(strings.Repeat("a", 200))) > 80 {
		t.Fatal("names must be truncated")
	}
}

func TestResolveInsideRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	for name, path := range map[string]string{
		"parent":      "../outside.wav",
		"deep parent": "recordings/../../outside.wav",
		"absolute":    "/etc/passwd",
		"empty":       "",
	} {
		if _, err := ResolveInside(root, path); err == nil {
			t.Fatalf("%s: ResolveInside(%q) must fail", name, path)
		}
	}
	resolved, err := ResolveInside(root, "recordings/a.wav")
	if err != nil {
		t.Fatalf("ResolveInside(valid) error = %v", err)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("Abs() error = %v", err)
	}
	if !strings.HasPrefix(resolved, absoluteRoot) {
		t.Fatalf("resolved %q is not under %q", resolved, absoluteRoot)
	}
}

func TestRecordRequiresConfiguration(t *testing.T) {
	ctx := context.Background()
	if _, err := Record(ctx, Options{Directory: t.TempDir()}); err == nil {
		t.Fatal("Record() must require a media URL")
	}
	if _, err := Record(ctx, Options{
		MediaURL: "wss://127.0.0.1:7575/x", Directory: t.TempDir(),
	}); err == nil {
		t.Fatal("Record() must require an authenticated HTTP client")
	}
}

func TestRecordFailsBeforeCreatingAFile(t *testing.T) {
	// A failed dial must not leave a stray empty WAV behind.
	directory := t.TempDir()
	if _, err := Record(context.Background(), Options{
		MediaURL: "wss://127.0.0.1:1/nope", Directory: directory, Name: "x",
	}); err == nil {
		t.Fatal("Record() must fail without a client")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("a failed recording left files behind: %v", entries)
	}
}
