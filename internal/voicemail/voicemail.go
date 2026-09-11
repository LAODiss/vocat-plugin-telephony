package voicemail

import (
	"context"
	"net/http"
	"time"

	"vocat-plugin-telephony/internal/recorder"
)

// Options controls one voicemail session.
type Options struct {
	MediaURL       string
	HTTPClient     *http.Client
	GreetingPath   string
	MaxDuration    time.Duration
	SilenceTimeout time.Duration
	Directory      string
	Name           string
}

// Result describes a finished recording.
type Result struct {
	Path     string
	Bytes    int64
	Duration time.Duration
}

// Record plays the greeting and records the caller. It is a thin wrapper over
// internal/recorder with voicemail's defaults: a silence timeout, because a
// caller who walks away must not hold the line open.
func Record(ctx context.Context, options Options) (Result, error) {
	if options.MaxDuration <= 0 {
		options.MaxDuration = 60 * time.Second
	}
	if options.SilenceTimeout <= 0 {
		options.SilenceTimeout = 8 * time.Second
	}
	result, err := recorder.Record(ctx, recorder.Options{
		MediaURL:       options.MediaURL,
		HTTPClient:     options.HTTPClient,
		GreetingPath:   options.GreetingPath,
		MaxDuration:    options.MaxDuration,
		SilenceTimeout: options.SilenceTimeout,
		Directory:      options.Directory,
		Name:           options.Name,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Path: result.Path, Bytes: result.Bytes, Duration: result.Duration}, nil
}
