package wav

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestMonoRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mono.wav")
	writer, err := Create(path, 1, 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	samples := []int16{0, 1000, -1000, 32767, -32768, 42}
	if err := writer.WriteMono(samples); err != nil {
		t.Fatalf("WriteMono() error = %v", err)
	}
	result, err := writer.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if result.Bytes != int64(len(samples)*2+HeaderBytes) {
		t.Fatalf("Bytes = %d", result.Bytes)
	}
	if result.Samples != int64(len(samples)) {
		t.Fatalf("Samples = %d, want %d", result.Samples, len(samples))
	}
	// The reader must accept what the writer produces, otherwise a recorded
	// message could not be reused as a greeting.
	decoded, err := ReadMono(path)
	if err != nil {
		t.Fatalf("ReadMono() error = %v", err)
	}
	for index := range samples {
		if decoded[index] != samples[index] {
			t.Fatalf("sample %d = %d, want %d", index, decoded[index], samples[index])
		}
	}
}

func TestStereoInterleavesAndPads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stereo.wav")
	writer, err := Create(path, 2, 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	// A shorter right channel must be zero-padded, not truncate the frame.
	if err := writer.WriteStereo([]int16{100, 200, 300}, []int16{-1}); err != nil {
		t.Fatalf("WriteStereo() error = %v", err)
	}
	result, err := writer.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if result.Samples != 3 {
		t.Fatalf("Samples = %d, want 3 per channel", result.Samples)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got := binary.LittleEndian.Uint16(content[22:]); got != 2 {
		t.Fatalf("channels = %d, want 2", got)
	}
	want := []int16{100, -1, 200, 0, 300, 0}
	for index, expected := range want {
		got := int16(binary.LittleEndian.Uint16(content[HeaderBytes+index*2:]))
		if got != expected {
			t.Fatalf("interleaved sample %d = %d, want %d", index, got, expected)
		}
	}
}

func TestHeaderDeclaresMono8kHz16Bit(t *testing.T) {
	// vocat's PCM bridge is 8 kHz mono 16-bit; a mismatched header plays as
	// noise on a live call.
	path := filepath.Join(t.TempDir(), "a.wav")
	writer, err := Create(path, 1, 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := writer.WriteMono([]int16{1, 2, 3}); err != nil {
		t.Fatalf("WriteMono() error = %v", err)
	}
	if _, err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content[0:4]) != "RIFF" || string(content[8:12]) != "WAVE" || string(content[36:40]) != "data" {
		t.Fatalf("not a WAV file: %q", content[:44])
	}
	if got := binary.LittleEndian.Uint16(content[22:]); got != 1 {
		t.Fatalf("channels = %d", got)
	}
	if got := binary.LittleEndian.Uint32(content[24:]); got != SampleRate {
		t.Fatalf("sample rate = %d", got)
	}
	if got := binary.LittleEndian.Uint16(content[34:]); got != BitsPerSample {
		t.Fatalf("bits = %d", got)
	}
	dataSize := binary.LittleEndian.Uint32(content[40:])
	if riff := binary.LittleEndian.Uint32(content[4:]); riff != dataSize+HeaderBytes-8 {
		t.Fatalf("RIFF size %d inconsistent with data size %d", riff, dataSize)
	}
}

func TestSizeCapStopsWithoutFailing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capped.wav")
	// Room for exactly two mono samples.
	writer, err := Create(path, 1, 4)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := writer.WriteMono([]int16{1, 2}); err != nil {
		t.Fatalf("first WriteMono() error = %v", err)
	}
	// Over the cap: dropped, not an error, because what is recorded so far is
	// still a valid file.
	if err := writer.WriteMono([]int16{3, 4}); err != nil {
		t.Fatalf("over-cap WriteMono() must not fail, got %v", err)
	}
	if !writer.Truncated() {
		t.Fatal("Truncated() must report the cap was hit")
	}
	result, err := writer.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if result.Bytes != 4+HeaderBytes {
		t.Fatalf("Bytes = %d, want %d", result.Bytes, 4+HeaderBytes)
	}
}

func TestEmptyRecordingIsRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.wav")
	writer, err := Create(path, 1, 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	// A call that carried no audio must not leave a file the UI would offer.
	if err := writer.WriteMono(nil); err != nil {
		t.Fatalf("WriteMono(nil) error = %v", err)
	}
	result, err := writer.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if result.Path != "" || result.Bytes != 0 {
		t.Fatalf("empty recording reported a result: %+v", result)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty file was not removed (stat err = %v)", err)
	}
}

func TestCloseIsIdempotentAndWriteAfterCloseFails(t *testing.T) {
	writer, err := Create(filepath.Join(t.TempDir(), "a.wav"), 1, 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := writer.WriteMono([]int16{1}); err != nil {
		t.Fatalf("WriteMono() error = %v", err)
	}
	if _, err := writer.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if _, err := writer.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := writer.WriteMono([]int16{1}); err == nil {
		t.Fatal("WriteMono() after Close() must fail")
	}
}

func TestChannelMismatchIsRejected(t *testing.T) {
	directory := t.TempDir()
	mono, err := Create(filepath.Join(directory, "m.wav"), 1, 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer mono.Close()
	if err := mono.WriteStereo([]int16{1}, []int16{1}); err == nil {
		t.Fatal("WriteStereo on a mono writer must fail")
	}
	stereo, err := Create(filepath.Join(directory, "s.wav"), 2, 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer stereo.Close()
	if err := stereo.WriteMono([]int16{1}); err == nil {
		t.Fatal("WriteMono on a stereo writer must fail")
	}
	if _, err := Create(filepath.Join(directory, "x.wav"), 3, 0); err == nil {
		t.Fatal("Create() must reject an unsupported channel count")
	}
}

func TestCreateRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.wav")
	first, err := Create(path, 1, 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer first.Close()
	// Silently overwriting a recording would lose evidence.
	if _, err := Create(path, 1, 0); err == nil {
		t.Fatal("Create() must refuse an existing path")
	}
}

func TestReadMonoRejectsWrongFormats(t *testing.T) {
	directory := t.TempDir()
	write := func(name string, channels uint16, rate uint32, bits uint16) string {
		path := filepath.Join(directory, name)
		header := buildHeader(1, 0)
		binary.LittleEndian.PutUint16(header[22:], channels)
		binary.LittleEndian.PutUint32(header[24:], rate)
		binary.LittleEndian.PutUint16(header[34:], bits)
		if err := os.WriteFile(path, header, 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		return path
	}
	if _, err := ReadMono(write("stereo.wav", 2, SampleRate, 16)); err == nil {
		t.Fatal("a stereo file must be rejected as a greeting")
	}
	if _, err := ReadMono(write("rate.wav", 1, 44100, 16)); err == nil {
		t.Fatal("44.1 kHz must be rejected")
	}
	if _, err := ReadMono(write("bits.wav", 1, SampleRate, 8)); err == nil {
		t.Fatal("8-bit must be rejected")
	}
	junk := filepath.Join(directory, "junk.wav")
	if err := os.WriteFile(junk, []byte("this is definitely not a wav file"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := ReadMono(junk); err == nil {
		t.Fatal("a non-WAV file must be rejected")
	}
	if _, err := ReadMono(filepath.Join(directory, "missing.wav")); err == nil {
		t.Fatal("a missing file must be reported")
	}
}

func TestReadMonoSkipsExtraChunks(t *testing.T) {
	// Many encoders insert a LIST chunk before data, so assuming data starts at
	// byte 44 would read the wrong bytes.
	path := filepath.Join(t.TempDir(), "list.wav")
	samples := []int16{5, -5, 500}
	list := []byte("INFOhello!!!")
	dataBytes := len(samples) * 2
	total := 12 + 8 + 16 + 8 + len(list) + 8 + dataBytes

	buffer := make([]byte, 0, total)
	buffer = append(buffer, []byte("RIFF")...)
	buffer = appendU32(buffer, uint32(total-8))
	buffer = append(buffer, []byte("WAVE")...)
	buffer = append(buffer, []byte("fmt ")...)
	buffer = appendU32(buffer, 16)
	format := make([]byte, 16)
	binary.LittleEndian.PutUint16(format[0:], 1)
	binary.LittleEndian.PutUint16(format[2:], 1)
	binary.LittleEndian.PutUint32(format[4:], SampleRate)
	binary.LittleEndian.PutUint32(format[8:], SampleRate*2)
	binary.LittleEndian.PutUint16(format[12:], 2)
	binary.LittleEndian.PutUint16(format[14:], BitsPerSample)
	buffer = append(buffer, format...)
	buffer = append(buffer, []byte("LIST")...)
	buffer = appendU32(buffer, uint32(len(list)))
	buffer = append(buffer, list...)
	buffer = append(buffer, []byte("data")...)
	buffer = appendU32(buffer, uint32(dataBytes))
	for _, sample := range samples {
		buffer = appendU16(buffer, uint16(sample))
	}
	if err := os.WriteFile(path, buffer, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	decoded, err := ReadMono(path)
	if err != nil {
		t.Fatalf("ReadMono() error = %v", err)
	}
	if len(decoded) != len(samples) {
		t.Fatalf("decoded %d samples, want %d", len(decoded), len(samples))
	}
	for index := range samples {
		if decoded[index] != samples[index] {
			t.Fatalf("sample %d = %d, want %d", index, decoded[index], samples[index])
		}
	}
}

func TestResultSeconds(t *testing.T) {
	if got := (Result{Samples: SampleRate * 3}).Seconds(); got != 3 {
		t.Fatalf("Seconds() = %d, want 3", got)
	}
	if got := (Result{Samples: SampleRate / 2}).Seconds(); got != 0 {
		t.Fatalf("Seconds() = %d, want 0 for a sub-second recording", got)
	}
}

func appendU32(buffer []byte, value uint32) []byte {
	var scratch [4]byte
	binary.LittleEndian.PutUint32(scratch[:], value)
	return append(buffer, scratch[:]...)
}

func appendU16(buffer []byte, value uint16) []byte {
	var scratch [2]byte
	binary.LittleEndian.PutUint16(scratch[:], value)
	return append(buffer, scratch[:]...)
}
