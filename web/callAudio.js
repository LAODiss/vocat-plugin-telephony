/* Browser side of the call audio bridge, for the vocat telephony plugin.
 *
 * vocat exposes an active call's audio as a WebSocket carrying raw
 * little-endian signed 16-bit mono PCM at 8 kHz in both directions, with no
 * framing. Two AudioWorklets do the rate conversion, because an AudioContext
 * runs at the hardware rate and there is no resampler server-side.
 *
 * Loaded as a classic script, not a module: plugin assets are served straight
 * from the ZIP with no bundler.
 */
"use strict";

/* Worklets live beside this file under /plugin-assets/<id>/web/. Deriving the
 * base from the current script keeps the paths correct without hardcoding the
 * plugin id. */
var WORKLET_BASE = (function () {
  var scripts = document.getElementsByTagName("script");
  for (var i = scripts.length - 1; i >= 0; i--) {
    var src = scripts[i].src || "";
    if (src.indexOf("callAudio.js") >= 0) {
      return src.slice(0, src.lastIndexOf("/") + 1);
    }
  }
  return "";
})();

/* CallAudio owns the microphone, the AudioContext and the media socket for
 * exactly one call. Create one per call and always call stop(). */
function CallAudio(events) {
  this.events = events || {};
  this.context = null;
  this.socket = null;
  this.micStream = null;
  this.capture = null;
  this.playback = null;
  this.source = null;
  this.stopped = false;
  this.status = "idle";
}

CallAudio.prototype.setStatus = function (status, detail) {
  if (this.status === status) return;
  this.status = status;
  if (this.events.onStatus) this.events.onStatus(status, detail);
};

/* Reports whether this browser can carry call audio, and why not if it cannot.
 * The distinction matters: an insecure origin is a policy decision the operator
 * can fix, an old browser is not. */
CallAudio.support = function () {
  if (typeof window === "undefined") return { ok: false, reason: "unsupported" };
  var hasAudio = typeof window.AudioContext !== "undefined";
  var hasSocket = typeof window.WebSocket !== "undefined";
  var hasMic = !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
  if (hasAudio && hasSocket && hasMic) return { ok: true };
  // Browsers only expose navigator.mediaDevices in a secure context. Plain HTTP
  // on a LAN address is not one, so the microphone is unreachable no matter how
  // capable the browser is.
  if (!hasMic && window.isSecureContext === false) {
    return { ok: false, reason: "insecure-context" };
  }
  return { ok: false, reason: "unsupported" };
};

/* mediaURL builds the same-origin WebSocket URL for a call's PCM bridge. */
CallAudio.mediaURL = function (deviceID, callID) {
  var scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  return scheme + "//" + window.location.host +
    "/api/devices/" + encodeURIComponent(deviceID) +
    "/calls/media?call_id=" + encodeURIComponent(callID);
};

CallAudio.prototype.start = function (deviceID, callID) {
  var self = this;
  if (this.context || this.socket) {
    return Promise.reject(new Error("音频通道已在运行"));
  }
  this.stopped = false;
  this.setStatus("connecting");

  // Ask for the microphone first: it is the only step that prompts the user, and
  // failing before opening a socket keeps teardown simple.
  return navigator.mediaDevices.getUserMedia({
    audio: {
      channelCount: 1,
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
    },
    video: false,
  }).then(function (stream) {
    self.micStream = stream;
    self.context = new AudioContext();
    return self.context.audioWorklet.addModule(WORKLET_BASE + "call-capture-processor.js");
  }).then(function () {
    return self.context.audioWorklet.addModule(WORKLET_BASE + "call-playback-processor.js");
  }).then(function () {
    // Autoplay policies can leave a fresh context suspended even after a user
    // gesture, which would silently mute the call.
    if (self.context.state === "suspended") return self.context.resume();
  }).then(function () {
    return self.openSocket(deviceID, callID);
  }).then(function () {
    if (self.stopped) return;
    self.wireGraph();
    self.setStatus("live");
  }).catch(function (error) {
    self.setStatus("error", error && error.message ? error.message : String(error));
    return self.stop().then(function () { throw error; });
  });
};

CallAudio.prototype.openSocket = function (deviceID, callID) {
  var self = this;
  return new Promise(function (resolve, reject) {
    var socket = new WebSocket(CallAudio.mediaURL(deviceID, callID));
    socket.binaryType = "arraybuffer";
    self.socket = socket;

    var timer = window.setTimeout(function () {
      cleanup();
      reject(new Error("音频连接超时"));
    }, 10000);
    function cleanup() {
      window.clearTimeout(timer);
      socket.removeEventListener("open", onOpen);
      socket.removeEventListener("close", onClose);
      socket.removeEventListener("error", onError);
    }
    function onOpen() { cleanup(); resolve(); }
    function onClose() { cleanup(); reject(new Error("服务端关闭了音频连接")); }
    function onError() { cleanup(); reject(new Error("音频连接建立失败")); }
    socket.addEventListener("open", onOpen);
    socket.addEventListener("close", onClose);
    socket.addEventListener("error", onError);
  });
};

CallAudio.prototype.wireGraph = function () {
  var self = this;
  var socket = this.socket;

  this.playback = new AudioWorkletNode(this.context, "call-playback-processor", {
    numberOfInputs: 0, numberOfOutputs: 1, outputChannelCount: [1],
  });
  this.playback.port.onmessage = function (event) {
    var data = event.data;
    if (data && data.type === "underrun" && self.events.onUnderrun) {
      self.events.onUnderrun(data.count);
    }
  };
  this.playback.connect(this.context.destination);

  this.capture = new AudioWorkletNode(this.context, "call-capture-processor", {
    numberOfInputs: 1, numberOfOutputs: 0,
  });
  this.capture.port.onmessage = function (event) {
    if (socket.readyState !== WebSocket.OPEN) return;
    // Drop frames instead of queueing when the socket is congested; stale audio
    // is worse than a brief gap on a live call.
    if (socket.bufferedAmount > 64 * 1024) return;
    socket.send(event.data);
  };
  this.source = this.context.createMediaStreamSource(this.micStream);
  this.source.connect(this.capture);

  socket.onmessage = function (event) {
    if (!(event.data instanceof ArrayBuffer) || event.data.byteLength < 2) return;
    // Odd lengths cannot be whole 16-bit samples.
    var usable = event.data.byteLength - (event.data.byteLength % 2);
    var buffer = usable === event.data.byteLength ? event.data : event.data.slice(0, usable);
    if (self.playback) self.playback.port.postMessage(buffer, [buffer]);
  };
  socket.onclose = function () {
    if (!self.stopped) self.setStatus("closed");
    void self.stop();
  };
  socket.onerror = function () {
    if (!self.stopped) self.setStatus("error", "音频连接异常");
  };
};

/* Mutes the microphone without dropping the call or the socket. */
CallAudio.prototype.setMuted = function (muted) {
  if (this.capture) this.capture.port.postMessage({ type: "mute", value: !!muted });
  // Also gate the track itself, so a muted call cannot leak audio if the
  // worklet is replaced or misbehaves.
  if (this.micStream) {
    var tracks = this.micStream.getAudioTracks();
    for (var i = 0; i < tracks.length; i++) tracks[i].enabled = !muted;
  }
};

/* Releases the microphone, worklets, context and socket. Safe to call twice. */
CallAudio.prototype.stop = function () {
  var self = this;
  if (this.stopped) return Promise.resolve();
  this.stopped = true;

  if (this.socket) {
    this.socket.onmessage = null;
    this.socket.onclose = null;
    this.socket.onerror = null;
    if (this.socket.readyState === WebSocket.OPEN ||
        this.socket.readyState === WebSocket.CONNECTING) {
      this.socket.close(1000, "call ended");
    }
    this.socket = null;
  }
  if (this.source) { this.source.disconnect(); this.source = null; }
  if (this.capture) {
    this.capture.port.onmessage = null;
    this.capture.disconnect();
    this.capture = null;
  }
  if (this.playback) {
    this.playback.port.onmessage = null;
    this.playback.disconnect();
    this.playback = null;
  }
  // Stopping tracks is what actually turns off the browser's recording
  // indicator, so it must happen even if closing the context fails.
  if (this.micStream) {
    var tracks = this.micStream.getTracks();
    for (var i = 0; i < tracks.length; i++) tracks[i].stop();
    this.micStream = null;
  }
  var closing = Promise.resolve();
  if (this.context) {
    var context = this.context;
    this.context = null;
    closing = context.close().catch(function () { /* already closed is fine */ });
  }
  return closing.then(function () {
    if (self.status !== "error" && self.status !== "closed") self.setStatus("idle");
  });
};

window.CallAudio = CallAudio;
