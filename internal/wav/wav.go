// Package wav reads and writes the one audio format this plugin handles:
// mono 16-bit PCM at 8 kHz, matching vocat's IMS media bridge.
//
// It exists so voicemail and call recording share exactly one implementation.
// Both need streaming writes (a call's length is unknown until it ends) and a
// strict reader (a greeting in the wrong format plays as noise on a live call).
package wav

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
)

const (
	// SampleRate is vocat's PCM bridge rate. AMR-WB negotiates 16 kHz on the
	// wire, but the bridge always hands over 8 kHz mono.
	SampleRate = 8000
	// BitsPerSample is fixed; the bridge is signed 16-bit.
	BitsPerSample = 16
	// HeaderBytes is the size of the canonical 44-byte RIFF/WAVE header.
	HeaderBytes = 44
)

// Result describes a finished file.
type Result struct {
	Path  string
	Bytes int64
	// Samples is the per-channel sample count, so a caller can derive duration
	// without reopening the file.
	Samples int64
}

// Duration in seconds, rounded down.
func (result Result) Seconds() int {
	return int(result.Samples / SampleRate)
}

// Writer streams interleaved PCM into a WAV file, patching the RIFF sizes on
// close. It never buffers a whole call in memory.
type Writer struct {
	file     *os.File
	path     string
	channels int
	// maxBytes caps the data chunk. Reaching it stops growth rather than
	// failing, because the audio recorded so far is still a valid file.
	maxBytes int64

	mu        sync.Mutex
	dataBytes int64
	truncated bool
	closed    bool
	scratch   []byte
}

// Create opens a new file. channels is 1 for a single stream or 2 to keep the
// two call directions separate. An existing path is an error, so a caller can
// never silently overwrite a recording.
func Create(path string, channels int, maxBytes int64) (*Writer, error) {
	if channels != 1 && channels != 2 {
		return nil, fmt.Errorf("wav: channels must be 1 or 2, got %d", channels)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("wav: create file: %w", err)
	}
	// Reserve the header; sizes are unknown until the call ends.
	if _, err := file.Write(make([]byte, HeaderBytes)); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("wav: reserve header: %w", err)
	}
	return &Writer{file: file, path: path, channels: channels, maxBytes: maxBytes}, nil
}

// WriteMono appends samples to a single-channel file.
func (writer *Writer) WriteMono(samples []int16) error {
	if writer.channels != 1 {
		return errors.New("wav: WriteMono on a stereo writer")
	}
	return writer.append(samples, nil)
}

// WriteStereo appends one time-aligned frame, left and right. A shorter side is
// zero-padded, which is what silence sounds like.
func (writer *Writer) WriteStereo(left, right []int16) error {
	if writer.channels != 2 {
		return errors.New("wav: WriteStereo on a mono writer")
	}
	return writer.append(left, right)
}

func (writer *Writer) append(left, right []int16) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return errors.New("wav: writer is closed")
	}
	count := len(left)
	if writer.channels == 2 && len(right) > count {
		count = len(right)
	}
	if count == 0 {
		return nil
	}
	needed := int64(count) * int64(writer.channels) * (BitsPerSample / 8)
	if writer.maxBytes > 0 && writer.dataBytes+needed > writer.maxBytes {
		writer.truncated = true
		return nil
	}
	if int64(cap(writer.scratch)) < needed {
		writer.scratch = make([]byte, needed)
	}
	frame := writer.scratch[:needed]
	step := writer.channels * (BitsPerSample / 8)
	for index := 0; index < count; index++ {
		offset := index * step
		binary.LittleEndian.PutUint16(frame[offset:], uint16(at(left, index)))
		if writer.channels == 2 {
			binary.LittleEndian.PutUint16(frame[offset+2:], uint16(at(right, index)))
		}
	}
	if _, err := writer.file.Write(frame); err != nil {
		return fmt.Errorf("wav: write samples: %w", err)
	}
	writer.dataBytes += needed
	return nil
}

func at(samples []int16, index int) int16 {
	if index < len(samples) {
		return samples[index]
	}
	return 0
}

// Truncated reports whether the size cap stopped the recording early.
func (writer *Writer) Truncated() bool {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.truncated
}

// Close finalises the file. A recording that captured no audio is removed
// instead of leaving an empty file for the UI to offer.
func (writer *Writer) Close() (Result, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return Result{}, nil
	}
	writer.closed = true

	if writer.dataBytes == 0 {
		name := writer.file.Name()
		_ = writer.file.Close()
		_ = os.Remove(name)
		return Result{}, nil
	}
	header := buildHeader(writer.channels, writer.dataBytes)
	if _, err := writer.file.WriteAt(header, 0); err != nil {
		_ = writer.file.Close()
		return Result{}, fmt.Errorf("wav: patch header: %w", err)
	}
	if err := writer.file.Close(); err != nil {
		return Result{}, fmt.Errorf("wav: close file: %w", err)
	}
	perChannel := writer.dataBytes / int64(writer.channels) / (BitsPerSample / 8)
	return Result{
		Path:    writer.path,
		Bytes:   writer.dataBytes + HeaderBytes,
		Samples: perChannel,
	}, nil
}

func buildHeader(channels int, dataBytes int64) []byte {
	header := make([]byte, HeaderBytes)
	byteRate := uint32(SampleRate * channels * BitsPerSample / 8)
	blockAlign := uint16(channels * BitsPerSample / 8)

	copy(header[0:], "RIFF")
	binary.LittleEndian.PutUint32(header[4:], uint32(dataBytes+HeaderBytes-8))
	copy(header[8:], "WAVE")
	copy(header[12:], "fmt ")
	binary.LittleEndian.PutUint32(header[16:], 16)
	binary.LittleEndian.PutUint16(header[20:], 1) // PCM
	binary.LittleEndian.PutUint16(header[22:], uint16(channels))
	binary.LittleEndian.PutUint32(header[24:], SampleRate)
	binary.LittleEndian.PutUint32(header[28:], byteRate)
	binary.LittleEndian.PutUint16(header[32:], blockAlign)
	binary.LittleEndian.PutUint16(header[34:], BitsPerSample)
	copy(header[36:], "data")
	binary.LittleEndian.PutUint32(header[40:], uint32(dataBytes))
	return header
}

// ReadMono loads a mono 16-bit 8 kHz PCM WAV. It is strict about the format
// because a mismatched greeting would play as noise on a live call.
func ReadMono(path string) ([]int16, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wav: read file: %w", err)
	}
	if len(raw) < HeaderBytes || string(raw[0:4]) != "RIFF" || string(raw[8:12]) != "WAVE" {
		return nil, errors.New("wav: not a WAV file")
	}
	channels := binary.LittleEndian.Uint16(raw[22:])
	rate := binary.LittleEndian.Uint32(raw[24:])
	bits := binary.LittleEndian.Uint16(raw[34:])
	if channels != 1 || bits != BitsPerSample {
		return nil, fmt.Errorf("wav: must be mono %d-bit, got %d channel(s) %d-bit",
			BitsPerSample, channels, bits)
	}
	if rate != SampleRate {
		return nil, fmt.Errorf("wav: must be %d Hz, got %d Hz", SampleRate, rate)
	}
	// Walk the chunk list: many encoders insert a LIST chunk before data, so
	// assuming data starts at byte 44 would read the wrong bytes.
	offset := 12
	for offset+8 <= len(raw) {
		id := string(raw[offset : offset+4])
		size := int(binary.LittleEndian.Uint32(raw[offset+4:]))
		body := offset + 8
		if id == "data" {
			end := body + size
			if end > len(raw) {
				end = len(raw)
			}
			usable := (end - body) / 2
			samples := make([]int16, usable)
			for index := 0; index < usable; index++ {
				samples[index] = int16(binary.LittleEndian.Uint16(raw[body+index*2:]))
			}
			return samples, nil
		}
		offset = body + size
		if size%2 == 1 {
			offset++ // chunks are word-aligned
		}
	}
	return nil, errors.New("wav: no data chunk")
}
