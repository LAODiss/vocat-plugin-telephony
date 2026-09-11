// Package recorder captures a call's audio to a WAV file.
//
// The one honest limitation: this records vocat's WebSocket downlink, not the
// RTP stream. Only an already-answered call with negotiated media has that
// socket, and packets vocat's jitter buffer discarded never reach it. So a
// recording is a usable record of the conversation, not a faithful capture of
// the wire. vocat has no RTP-level hook a plugin could use instead.
package recorder

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vocat-plugin-telephony/internal/media"
	"vocat-plugin-telephony/internal/wav"
)

// Options controls one recording.
type Options struct {
	// MediaURL is the wss:// URL for the call's PCM bridge.
	MediaURL string
	// HTTPClient must carry the authenticated cookie jar, pinned TLS and
	// HTTP/1.1.
	HTTPClient *http.Client
	// GreetingPath is an optional 8 kHz mono 16-bit WAV played before recording.
	GreetingPath string
	// MaxDuration bounds the recording.
	MaxDuration time.Duration
	// SilenceTimeout ends the recording after this much quiet. Zero disables it,
	// which is what a full call recording wants; voicemail sets it so a caller
	// who walks away does not hold the line.
	SilenceTimeout time.Duration
	// HangupWhenDone asks the caller to end the call afterwards. Voicemail wants
	// this; recording an ongoing conversation does not.
	Directory string
	Name      string
}

// Result describes a finished recording. A zero Path means nothing was captured.
type Result struct {
	Path     string
	Bytes    int64
	Duration time.Duration
	// Truncated reports that the duration cap stopped it early.
	Truncated bool
}

// Record connects to a call's audio, optionally plays a greeting, then writes
// the conversation until silence, the duration cap, or the call ending.
func Record(ctx context.Context, options Options) (Result, error) {
	if options.MaxDuration <= 0 {
		options.MaxDuration = 5 * time.Minute
	}
	// The socket read is given its own budget beyond the recording window so a
	// clean shutdown can still finalise the file.
	sessionCtx, cancel := context.WithTimeout(ctx, options.MaxDuration+30*time.Second)
	defer cancel()

	session, err := media.Dial(sessionCtx, options.MediaURL, options.HTTPClient)
	if err != nil {
		return Result{}, err
	}
	defer session.Close()

	if options.GreetingPath != "" {
		if err := session.PlayFile(sessionCtx, options.GreetingPath); err != nil {
			// A missing or malformed greeting must not lose the recording.
			_ = err
		}
	}

	if err := os.MkdirAll(options.Directory, 0o700); err != nil {
		return Result{}, fmt.Errorf("recorder: create directory: %w", err)
	}
	path := filepath.Join(options.Directory, Sanitize(options.Name)+".wav")
	// Mono: the WebSocket downlink already carries the mixed call audio, so
	// there is no second stream to separate.
	writer, err := wav.Create(path, 1, 0)
	if err != nil {
		return Result{}, err
	}

	deadline := time.Now().Add(options.MaxDuration)
	lastVoice := time.Now()
	var samples int64

	for time.Now().Before(deadline) {
		readCtx, readCancel := context.WithTimeout(sessionCtx, 2*time.Second)
		frame, readErr := session.Read(readCtx)
		readCancel()

		if readErr != nil {
			// A closed socket means the call ended, which is a normal finish.
			if sessionCtx.Err() != nil || media.IsClosed(readErr) {
				break
			}
			// A read timeout is silence, not a failure.
			if options.SilenceTimeout > 0 && time.Since(lastVoice) > options.SilenceTimeout {
				break
			}
			continue
		}
		if err := writer.WriteMono(frame); err != nil {
			_, _ = writer.Close()
			return Result{}, err
		}
		samples += int64(len(frame))
		if media.Voiced(frame) {
			lastVoice = time.Now()
		} else if options.SilenceTimeout > 0 && time.Since(lastVoice) > options.SilenceTimeout {
			break
		}
	}

	truncated := !time.Now().Before(deadline)
	result, err := writer.Close()
	if err != nil {
		return Result{}, err
	}
	if result.Path == "" {
		// Nothing was captured; Close already removed the empty file.
		return Result{}, nil
	}
	return Result{
		Path:      result.Path,
		Bytes:     result.Bytes,
		Duration:  time.Duration(result.Samples) * time.Second / wav.SampleRate,
		Truncated: truncated,
	}, nil
}

// Sanitize reduces a name to characters that are safe in a file name.
func Sanitize(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = time.Now().UTC().Format("20060102T150405Z")
	}
	var builder strings.Builder
	for _, character := range name {
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '-', character == '_':
			builder.WriteRune(character)
		default:
			builder.WriteRune('_')
		}
	}
	result := strings.Trim(builder.String(), "_")
	if result == "" {
		result = "recording"
	}
	if len(result) > 80 {
		result = result[:80]
	}
	return result
}

// ResolveInside maps a stored relative path to an absolute one inside root,
// refusing anything that escapes it. A tampered state file must not become an
// arbitrary file read.
func ResolveInside(root, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("recorder: empty path")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(absoluteRoot, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(absoluteRoot, candidate)
	if err != nil {
		return "", err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("recorder: path %q escapes %q", path, root)
	}
	return candidate, nil
}
