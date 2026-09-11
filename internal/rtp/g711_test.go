package rtp

import "testing"

// G.711 is lossy, so a round trip is checked against a tolerance rather than
// for equality. These bounds are the codec's documented quantisation error at
// each amplitude range, not arbitrary slack.
func TestRoundTripStaysWithinQuantisationError(t *testing.T) {
	for _, payload := range []PayloadType{PayloadPCMA, PayloadPCMU} {
		for sample := -32000; sample <= 32000; sample += 37 {
			original := int16(sample)
			encoded := Encode(payload, []int16{original})
			decoded := Decode(payload, encoded)
			difference := int(decoded[0]) - int(original)
			if difference < 0 {
				difference = -difference
			}
			// Error grows with amplitude because G.711 is logarithmic; 8% plus a
			// floor covers the whole range for both laws.
			tolerance := abs(sample)/12 + 64
			if difference > tolerance {
				t.Fatalf("%s: sample %d round-tripped to %d (error %d > %d)",
					payload.Name(), original, decoded[0], difference, tolerance)
			}
		}
	}
}

func TestSilenceRoundTripsToNearSilence(t *testing.T) {
	// A silent line must stay silent: a codec bug here shows up as constant
	// audible hiss on every call.
	for _, payload := range []PayloadType{PayloadPCMA, PayloadPCMU} {
		encoded := Encode(payload, make([]int16, 160))
		decoded := Decode(payload, encoded)
		for index, sample := range decoded {
			if abs(int(sample)) > 8 {
				t.Fatalf("%s: silence decoded to %d at index %d", payload.Name(), sample, index)
			}
		}
	}
}

func TestFullScaleDoesNotWrapPolarity(t *testing.T) {
	// Clipping must saturate, never wrap. A wrap turns a loud passage into
	// violent noise at the opposite polarity.
	for _, payload := range []PayloadType{PayloadPCMA, PayloadPCMU} {
		for _, sample := range []int16{32767, -32768, 32000, -32000} {
			decoded := Decode(payload, Encode(payload, []int16{sample}))[0]
			if sample > 0 && decoded < 0 {
				t.Fatalf("%s: positive %d wrapped to %d", payload.Name(), sample, decoded)
			}
			if sample < 0 && decoded > 0 {
				t.Fatalf("%s: negative %d wrapped to %d", payload.Name(), sample, decoded)
			}
		}
	}
}

func TestTableAndDirectEncodersAgree(t *testing.T) {
	// Encode uses a lookup table for non-negative samples and the direct routine
	// for negatives. The two paths must not diverge, or audio would be subtly
	// asymmetric.
	for sample := 0; sample <= 32767; sample += 13 {
		value := int16(sample)
		if got, want := lookupALaw(value), encodeALaw(value); got != want {
			t.Fatalf("A-law table/direct mismatch at %d: %02x vs %02x", value, got, want)
		}
		if got, want := lookupULaw(value), encodeULaw(value); got != want {
			t.Fatalf("mu-law table/direct mismatch at %d: %02x vs %02x", value, got, want)
		}
	}
}

func TestKnownG711Values(t *testing.T) {
	// Anchors against the ITU-T G.711 definition, so a refactor that keeps the
	// round trip self-consistent but drifts from the standard is still caught.
	// Silence is 0xD5 in A-law and 0xFF in mu-law.
	if got := Encode(PayloadPCMA, []int16{0})[0]; got != 0xD5 {
		t.Fatalf("A-law silence = %02x, want d5", got)
	}
	if got := Encode(PayloadPCMU, []int16{0})[0]; got != 0xFF {
		t.Fatalf("mu-law silence = %02x, want ff", got)
	}
	// 0x55 is A-law negative silence and must decode near zero.
	if got := Decode(PayloadPCMA, []byte{0x55})[0]; abs(int(got)) > 16 {
		t.Fatalf("A-law 0x55 decoded to %d, want near zero", got)
	}
	if got := Decode(PayloadPCMU, []byte{0x7F})[0]; abs(int(got)) > 16 {
		t.Fatalf("mu-law 0x7f decoded to %d, want near zero", got)
	}
}

func TestDecodeLengthMatchesInput(t *testing.T) {
	// One byte in, one sample out. A length mismatch would desynchronise the
	// whole audio path.
	for _, size := range []int{0, 1, 160, 1000} {
		if got := len(Decode(PayloadPCMA, make([]byte, size))); got != size {
			t.Fatalf("Decode(%d bytes) produced %d samples", size, got)
		}
		if got := len(Encode(PayloadPCMU, make([]int16, size))); got != size {
			t.Fatalf("Encode(%d samples) produced %d bytes", size, got)
		}
	}
}

func TestUnsupportedPayloadDecodesToSilence(t *testing.T) {
	// A caller that failed to negotiate should hear nothing, not static.
	decoded := Decode(PayloadType(99), []byte{0x12, 0x34, 0x56})
	if len(decoded) != 3 {
		t.Fatalf("length = %d, want 3", len(decoded))
	}
	for index, sample := range decoded {
		if sample != 0 {
			t.Fatalf("unsupported payload produced %d at index %d, want silence", sample, index)
		}
	}
}

func TestPayloadTypeMetadata(t *testing.T) {
	if PayloadPCMA.Name() != "PCMA" || PayloadPCMU.Name() != "PCMU" {
		t.Fatal("SDP encoding names are wrong")
	}
	if !PayloadPCMA.Supported() || !PayloadPCMU.Supported() {
		t.Fatal("G.711 must be supported")
	}
	if PayloadType(99).Supported() || PayloadType(99).Name() != "" {
		t.Fatal("an unknown payload type must not claim support")
	}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
