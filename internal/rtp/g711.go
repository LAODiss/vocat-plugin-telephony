// G.711 A-law and mu-law codecs.
//
// Both are 8 kHz, 8 bits per sample, which is exactly what vocat's PCM bridge
// carries, so no resampling is ever needed between a softphone and vocat — only
// this companding. The tables are computed once at init rather than written out,
// because a hand-typed 256-entry table is a silent-corruption risk that is
// impossible to spot in review.
package rtp

// PayloadType identifies the RTP payload format.
type PayloadType uint8

const (
	// PayloadPCMU is G.711 mu-law, RTP payload type 0.
	PayloadPCMU PayloadType = 0
	// PayloadPCMA is G.711 A-law, RTP payload type 8.
	PayloadPCMA PayloadType = 8
)

// Name returns the SDP encoding name.
func (payload PayloadType) Name() string {
	switch payload {
	case PayloadPCMA:
		return "PCMA"
	case PayloadPCMU:
		return "PCMU"
	default:
		return ""
	}
}

// Supported reports whether this gateway can transcode the payload type.
func (payload PayloadType) Supported() bool {
	return payload == PayloadPCMA || payload == PayloadPCMU
}

var (
	alawToLinearTable [256]int16
	ulawToLinearTable [256]int16
	linearToALawTable [8192]uint8
	linearToULawTable [8192]uint8
)

func init() {
	for value := 0; value < 256; value++ {
		alawToLinearTable[value] = decodeALaw(uint8(value))
		ulawToLinearTable[value] = decodeULaw(uint8(value))
	}
	// The encoder tables are indexed by the top 13 bits of the magnitude, which
	// is all G.711 resolves; the sign is applied separately.
	for index := 0; index < 8192; index++ {
		sample := int16(index << 2)
		linearToALawTable[index] = encodeALaw(sample)
		linearToULawTable[index] = encodeULaw(sample)
	}
}

// decodeALaw expands one A-law byte, per ITU-T G.711.
func decodeALaw(value uint8) int16 {
	value ^= 0x55
	magnitude := int32(value&0x0f) << 4
	exponent := (value & 0x70) >> 4
	switch exponent {
	case 0:
		magnitude += 8
	case 1:
		magnitude += 0x108
	default:
		magnitude += 0x108
		magnitude <<= exponent - 1
	}
	if value&0x80 == 0 {
		return int16(-magnitude)
	}
	return int16(magnitude)
}

// decodeULaw expands one mu-law byte, per ITU-T G.711.
func decodeULaw(value uint8) int16 {
	value = ^value
	magnitude := (int32(value&0x0f)<<3 + 0x84) << ((value & 0x70) >> 4)
	magnitude -= 0x84
	if value&0x80 != 0 {
		return int16(-magnitude)
	}
	return int16(magnitude)
}

func encodeALaw(sample int16) uint8 {
	const clip = 32635
	mask := uint8(0xd5)
	value := int32(sample)
	if value < 0 {
		// A-law is asymmetric around zero: negating and subtracting one keeps
		// the round trip stable at the boundary.
		value = -value - 1
		mask = 0x55
	}
	if value > clip {
		value = clip
	}
	var encoded uint8
	if value < 256 {
		encoded = uint8(value >> 4)
	} else {
		exponent := 1
		for threshold := int32(512); exponent < 7 && value >= threshold; threshold <<= 1 {
			exponent++
		}
		encoded = uint8(exponent<<4) | uint8((value>>(exponent+3))&0x0f)
	}
	return encoded ^ mask
}

func encodeULaw(sample int16) uint8 {
	const (
		bias = 0x84
		clip = 32635
	)
	value := int32(sample)
	sign := uint8(0)
	if value < 0 {
		value = -value
		sign = 0x80
	}
	if value > clip {
		value = clip
	}
	value += bias
	exponent := 7
	for mask := int32(0x4000); exponent > 0 && value&mask == 0; mask >>= 1 {
		exponent--
	}
	mantissa := uint8((value >> (exponent + 3)) & 0x0f)
	return ^(sign | uint8(exponent<<4) | mantissa)
}

// Decode expands a G.711 payload into signed 16-bit samples.
func Decode(payload PayloadType, encoded []byte) []int16 {
	samples := make([]int16, len(encoded))
	switch payload {
	case PayloadPCMA:
		for index, value := range encoded {
			samples[index] = alawToLinearTable[value]
		}
	case PayloadPCMU:
		for index, value := range encoded {
			samples[index] = ulawToLinearTable[value]
		}
	default:
		// An unsupported payload decodes to silence rather than noise: a caller
		// that failed to negotiate should hear nothing, not static.
		return make([]int16, len(encoded))
	}
	return samples
}

// Encode compresses signed 16-bit samples into a G.711 payload.
func Encode(payload PayloadType, samples []int16) []byte {
	encoded := make([]byte, len(samples))
	switch payload {
	case PayloadPCMA:
		for index, sample := range samples {
			encoded[index] = lookupALaw(sample)
		}
	case PayloadPCMU:
		for index, sample := range samples {
			encoded[index] = lookupULaw(sample)
		}
	default:
		// Silence in the requested format is not knowable without a codec, so
		// emit A-law silence, which is the more common default.
		for index := range encoded {
			encoded[index] = lookupALaw(0)
		}
	}
	return encoded
}

func lookupALaw(sample int16) uint8 {
	if sample < 0 {
		// Table lookups are on magnitude; recompute the rare negative-boundary
		// case directly to keep the asymmetry exact.
		return encodeALaw(sample)
	}
	return linearToALawTable[sample>>2]
}

func lookupULaw(sample int16) uint8 {
	if sample < 0 {
		return encodeULaw(sample)
	}
	return linearToULawTable[sample>>2]
}
