/**
 * Capture worklet: microphone -> 8 kHz signed 16-bit mono frames.
 *
 * vocat's PCM bridge only speaks 8 kHz while an AudioContext runs at the
 * hardware rate (typically 44.1 or 48 kHz), and there is no resampler on the
 * server. Downsampling here keeps that work off the main thread, so a busy
 * panel cannot cause audible gaps in the outgoing audio.
 *
 * Plain JavaScript on purpose: worklets are loaded as classic modules straight
 * from the plugin asset path and are never processed by a bundler.
 */

const TARGET_RATE = 8000;
// 20 ms at 8 kHz, matching the RTP packetisation vocat expects.
const FRAME_SAMPLES = 160;

class CallCaptureProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.ratio = sampleRate / TARGET_RATE;
    this.pending = new Float32Array(0);
    this.readPosition = 0;
    this.frame = new Int16Array(FRAME_SAMPLES);
    this.frameCount = 0;
    this.muted = false;
    this.port.onmessage = (event) => {
      const message = event.data;
      if (message && message.type === "mute") this.muted = Boolean(message.value);
    };
  }

  append(block) {
    const combined = new Float32Array(this.pending.length + block.length);
    combined.set(this.pending, 0);
    combined.set(block, this.pending.length);
    this.pending = combined;
  }

  emit(sample) {
    // Clamp before converting: a float slightly outside [-1, 1] would wrap
    // around into loud noise at the opposite polarity.
    const clamped = sample > 1 ? 1 : sample < -1 ? -1 : sample;
    this.frame[this.frameCount] = Math.round(clamped * 32767);
    this.frameCount += 1;
    if (this.frameCount === FRAME_SAMPLES) {
      const payload = new Int16Array(this.frame);
      this.port.postMessage(payload.buffer, [payload.buffer]);
      this.frameCount = 0;
    }
  }

  process(inputs) {
    const channel = inputs[0] && inputs[0][0];
    if (!channel || channel.length === 0) return true;
    if (this.muted) {
      // Keep emitting silence so the far end hears a muted line rather than a
      // frozen one, and so RTP timing stays continuous.
      this.append(new Float32Array(channel.length));
    } else {
      this.append(channel);
    }

    // Linear interpolation between neighbouring input samples. Not a brick-wall
    // filter, but well past what an 8 kHz narrowband voice channel can carry.
    while (this.readPosition + 1 < this.pending.length) {
      const index = Math.floor(this.readPosition);
      const fraction = this.readPosition - index;
      const current = this.pending[index];
      const next = this.pending[index + 1];
      this.emit(current + (next - current) * fraction);
      this.readPosition += this.ratio;
    }

    // Drop the samples already consumed, keeping the one the next interpolation
    // still needs.
    const consumed = Math.floor(this.readPosition);
    if (consumed > 0) {
      this.pending = this.pending.slice(consumed);
      this.readPosition -= consumed;
    }
    return true;
  }
}

registerProcessor("call-capture-processor", CallCaptureProcessor);
