/**
 * Playback worklet: 8 kHz signed 16-bit mono frames -> speaker.
 *
 * A pull model with a ring buffer, deliberately. Feeding each arriving
 * WebSocket frame into its own AudioBufferSourceNode produces audible clicks
 * whenever the network jitters; a small ring smooths that out and, when it does
 * run dry, substitutes silence instead of stalling the audio graph.
 *
 * Plain JavaScript on purpose: worklets are loaded as classic modules straight
 * from the plugin asset path and are never processed by a bundler.
 */

const SOURCE_RATE = 8000;
// 8 kHz mono: two seconds of jitter headroom.
const RING_CAPACITY = 8000 * 2;
// Wait for this much audio before starting, so the first frames of a call do
// not immediately underrun.
const PRIME_SAMPLES = 480; // 60 ms

class CallPlaybackProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.ratio = SOURCE_RATE / sampleRate;
    this.ring = new Float32Array(RING_CAPACITY);
    this.writeIndex = 0;
    this.available = 0;
    this.readPosition = 0;
    this.priming = true;
    this.underruns = 0;
    this.port.onmessage = (event) => {
      const data = event.data;
      if (data instanceof ArrayBuffer) {
        this.push(new Int16Array(data));
        return;
      }
      if (data && data.type === "reset") this.reset();
    };
  }

  reset() {
    this.ring.fill(0);
    this.writeIndex = 0;
    this.available = 0;
    this.readPosition = 0;
    this.priming = true;
  }

  push(samples) {
    for (let index = 0; index < samples.length; index += 1) {
      this.ring[this.writeIndex] = samples[index] / 32768;
      this.writeIndex = (this.writeIndex + 1) % RING_CAPACITY;
      if (this.available < RING_CAPACITY) {
        this.available += 1;
      }
      // On overflow `available` stays at capacity, so the unread window (derived
      // from writeIndex - available) slides forward on its own and the oldest
      // sample is dropped. That keeps latency bounded when the far end runs
      // ahead of playback.
    }
    if (this.priming && this.available >= PRIME_SAMPLES) this.priming = false;
  }

  readAt(offset) {
    const index = (this.writeIndex - this.available + offset + RING_CAPACITY * 2) % RING_CAPACITY;
    return this.ring[index];
  }

  process(_inputs, outputs) {
    const output = outputs[0];
    if (!output || output.length === 0) return true;
    const channel = output[0];

    if (this.priming || this.available < 2) {
      channel.fill(0);
      if (!this.priming && this.available < 2) {
        this.underruns += 1;
        // Re-prime after a dry spell so playback does not chatter in and out on
        // every single frame.
        this.priming = true;
        this.port.postMessage({ type: "underrun", count: this.underruns });
      }
      for (let index = 1; index < output.length; index += 1) output[index].set(channel);
      return true;
    }

    for (let index = 0; index < channel.length; index += 1) {
      const position = this.readPosition;
      const base = Math.floor(position);
      if (base + 1 >= this.available) {
        // Ran out mid-block: pad the remainder rather than reading stale audio.
        channel.fill(0, index);
        break;
      }
      const fraction = position - base;
      const current = this.readAt(base);
      const next = this.readAt(base + 1);
      channel[index] = current + (next - current) * fraction;
      this.readPosition += this.ratio;
    }

    const consumed = Math.floor(this.readPosition);
    if (consumed > 0) {
      this.available = Math.max(0, this.available - consumed);
      this.readPosition -= consumed;
    }
    for (let index = 1; index < output.length; index += 1) output[index].set(channel);
    return true;
  }
}

registerProcessor("call-playback-processor", CallPlaybackProcessor);
