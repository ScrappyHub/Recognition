// Recognition fingerprint shield.
//
// This file is the BODY of a function whose parameters are supplied by the host:
//   g      the global object (window, or a test double)
//   __cfg  { key: "<hex session key>", tel: "<hex telemetry name>", level: "off|standard|strict", sites: { "<host or registrable domain>": "off|standard|strict" }, suffixes: ["co.uk", ...] }
// It is injected into every frame before any page script runs (AddScriptToExecuteOnDocumentCreated).
//
// What it does (and does not do):
//  - "Farbling": canvas readbacks (toDataURL, toBlob, getImageData), WebGL readPixels and audio buffers get tiny
//    deterministic noise. The noise is seeded by (session key, top-level SITE), so it is stable on one site during a
//    session (nothing visibly breaks) but different on every other site and every browser session. A tracker embedded
//    on two sites therefore cannot link the visits, and a script cannot recognise you across sessions.
//  - Reduces high-entropy values: hardwareConcurrency, deviceMemory, WebGL vendor/renderer strings, User-Agent Client
//    Hints. Strict level also rounds screen size, removes the Battery API and the speech-voice list.
//  - Replaced functions keep their name, length and a native-looking toString.
//  - Any internal error falls back to the original behaviour: the shield never adds a new exception to a page.
//  - It does NOT hide fonts, GPU timing, or behaviour/network characteristics, and a determined script can detect
//    that noise is being applied. It reduces tracking surface; it is not anonymity.
//
// Telemetry: counts of intercepted calls are kept in a closure and exposed ONLY through a non-enumerable window property whose
// name contains the secret session key. The host reads (and resets) it with ExecuteScriptAsync. Nothing is ever sent with
// postMessage, because the host refuses every command that comes from web content.
// Not covered: dedicated/shared workers and service workers (document-start scripts do not run there).

"use strict";
if (!__cfg || typeof __cfg.key !== "string" || __cfg.key.length < 16) return;
// Only real web pages. Internal pages (data:/about:) and local files must keep exact canvas output, because the
// image tools export pixels with it.
if (!g.location || (g.location.protocol !== "https:" && g.location.protocol !== "http:")) return;

// ---- site identity (top-level registrable domain) ---------------------------------------------
var suffixSet = {};
(__cfg.suffixes || []).forEach(function (s) { suffixSet[s] = 1; });
function registrable(host) {
  host = String(host || "").toLowerCase();
  var l = host.split(".");
  if (l.length <= 2) return host;
  var last2 = l.slice(-2).join(".");
  if (suffixSet[last2] && l.length >= 3) return l.slice(-3).join(".");
  return last2;
}
function topHost() {
  try {
    if (g.top === g.self) return g.location.hostname;
    var ao = g.location.ancestorOrigins;
    if (ao && ao.length) return new g.URL(ao[ao.length - 1]).hostname;
  } catch (e) { /* cross-origin top without ancestorOrigins */ }
  try { if (g.document && g.document.referrer) return new g.URL(g.document.referrer).hostname; } catch (e2) { }
  return g.location.hostname;
}
var host = topHost();
var site = registrable(host);
var sites = __cfg.sites || {};
var chosen = Object.prototype.hasOwnProperty.call(sites, host) ? sites[host]
           : Object.prototype.hasOwnProperty.call(sites, site) ? sites[site] : __cfg.level;
if (chosen !== "standard" && chosen !== "strict") return;   // "off", missing or anything unexpected: do nothing
var level = chosen;

// ---- deterministic randomness (not cryptographic: it only has to be unpredictable without the session key) ----
function cyrb128(str) {
  var h1 = 1779033703, h2 = 3144134277, h3 = 1013904242, h4 = 2773480762;
  for (var i = 0, k; i < str.length; i++) {
    k = str.charCodeAt(i);
    h1 = h2 ^ Math.imul(h1 ^ k, 597399067); h2 = h3 ^ Math.imul(h2 ^ k, 2869860233);
    h3 = h4 ^ Math.imul(h3 ^ k, 951274213); h4 = h1 ^ Math.imul(h4 ^ k, 2716044179);
  }
  h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067); h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
  h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213); h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);
  return [(h1 ^ h2 ^ h3 ^ h4) >>> 0, (h2 ^ h1) >>> 0, (h3 ^ h1) >>> 0, (h4 ^ h1) >>> 0];
}
function sfc32(a, b, c, d) {
  return function () {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    var t = (a + b) | 0; a = b ^ (b >>> 9); b = (c + (c << 3)) | 0; c = (c << 21) | (c >>> 11);
    d = (d + 1) | 0; t = (t + d) | 0; c = (c + t) | 0;
    return (t >>> 0) / 4294967296;
  };
}
function rngFor(tag) { var s = cyrb128(__cfg.key + "|" + site + "|" + tag); return sfc32(s[0], s[1], s[2], s[3]); }

// ---- telemetry --------------------------------------------------------------------------------------
var counts = {};
function report(kind) { counts[kind] = (counts[kind] || 0) + 1; }
try {
  if (typeof __cfg.tel === "string" && __cfg.tel.length >= 16) Object.defineProperty(g, "__rc_" + __cfg.tel, {
    value: function () { var out = []; for (var k in counts) out.push(k + "=" + counts[k]); counts = {}; return out.join(","); },
    enumerable: false, configurable: false, writable: false
  });
} catch (e) { }

// ---- making replacements look native -----------------------------------------------------------
var natives = new WeakMap();
var origToString = g.Function.prototype.toString;
function nativeText(fn) { try { return origToString.call(fn); } catch (e) { return "function () { [native code] }"; } }
function rename(w, orig, name) {
  try { Object.defineProperty(w, "name", { value: name, configurable: true }); } catch (e) { }
  try { Object.defineProperty(w, "length", { value: orig.length, configurable: true }); } catch (e) { }
  natives.set(w, nativeText(orig));
  return w;
}
function wrapMethod(obj, name, make) {
  try {
    if (!obj) return false;
    var d = Object.getOwnPropertyDescriptor(obj, name);
    if (!d || typeof d.value !== "function") return false;
    var orig = d.value;
    d.value = rename(make(orig), orig, name);
    Object.defineProperty(obj, name, d);
    return true;
  } catch (e) { return false; }
}
function wrapGetter(obj, name, make) {
  try {
    if (!obj) return false;
    var d = Object.getOwnPropertyDescriptor(obj, name);
    if (!d || typeof d.get !== "function") return false;
    var orig = d.get;
    d.get = rename(make(orig), orig, "get " + name);
    Object.defineProperty(obj, name, d);
    return true;
  } catch (e) { return false; }
}
var newToString = function toString() {
  if (natives.has(this)) return natives.get(this);
  return origToString.call(this);
};
natives.set(newToString, nativeText(origToString));
try {
  var dts = Object.getOwnPropertyDescriptor(g.Function.prototype, "toString");
  dts.value = newToString; Object.defineProperty(g.Function.prototype, "toString", dts);
} catch (e) { }

// ---- noise primitives -------------------------------------------------------------------------------
// Flip the lowest bit of a few colour bytes (never alpha). The number of flips scales with the image size.
function noiseImage(data, w, h) {
  var px = w * h; if (!px || !data || data.length < px * 4) return;
  var rng = rngFor("canvas|" + w + "x" + h), n = Math.max(4, Math.min(512, (px / 1500) | 0));
  for (var k = 0; k < n; k++) {
    var idx = (rng() * px) | 0, ch = (rng() * 3) | 0;
    data[idx * 4 + ch] ^= 1;
  }
}
function noiseBytes(arr, tag) {
  var len = arr.length; if (!len) return;
  var rng = rngFor(tag + "|" + len), n = Math.max(2, Math.min(256, (len / 4000) | 0));
  for (var k = 0; k < n; k++) { var i = (rng() * len) | 0; arr[i] ^= 1; }
}
function noiseFloat(arr, tag, rel) {
  var len = arr.length; if (!len) return;
  var rng = rngFor(tag + "|" + len), step = Math.max(1, (len / 64) | 0);
  for (var i = (rng() * step) | 0; i < len; i += step) {
    var v = arr[i]; arr[i] = v === 0 ? (rng() - 0.5) * 1e-9 : v * (1 + (rng() - 0.5) * 2 * rel);
  }
}

// ---- canvas -------------------------------------------------------------------------------------------
var C2D = g.CanvasRenderingContext2D && g.CanvasRenderingContext2D.prototype;
var HCE = g.HTMLCanvasElement && g.HTMLCanvasElement.prototype;
var origGetImageData = C2D && C2D.getImageData;
var origGetContext = HCE && HCE.getContext;

function scratchOf(canvas) {
  try {
    var w = canvas.width, h = canvas.height;
    if (!w || !h || w * h > 16777216 || !origGetImageData || !origGetContext) return null;
    var s = g.document.createElement("canvas"); s.width = w; s.height = h;
    var ctx = origGetContext.call(s, "2d"); if (!ctx) return null;
    ctx.drawImage(canvas, 0, 0);
    var img = origGetImageData.call(ctx, 0, 0, w, h);
    noiseImage(img.data, w, h);
    ctx.putImageData(img, 0, 0);
    return s;
  } catch (e) { return null; }
}
wrapMethod(C2D, "getImageData", function (orig) {
  return function getImageData() {
    var img = orig.apply(this, arguments);
    try { noiseImage(img.data, img.width, img.height); report("canvas"); } catch (e) { }
    return img;
  };
});
wrapMethod(HCE, "toDataURL", function (orig) {
  return function toDataURL() { var s = scratchOf(this); report("canvas"); return orig.apply(s || this, arguments); };
});
wrapMethod(HCE, "toBlob", function (orig) {
  return function toBlob() { var s = scratchOf(this); report("canvas"); return orig.apply(s || this, arguments); };
});
var OC2D = g.OffscreenCanvasRenderingContext2D && g.OffscreenCanvasRenderingContext2D.prototype;
wrapMethod(OC2D, "getImageData", function (orig) {
  return function getImageData() {
    var img = orig.apply(this, arguments);
    try { noiseImage(img.data, img.width, img.height); report("canvas"); } catch (e) { }
    return img;
  };
});

// ---- WebGL ----------------------------------------------------------------------------------------------
["WebGLRenderingContext", "WebGL2RenderingContext"].forEach(function (n) {
  var P = g[n] && g[n].prototype; if (!P) return;
  wrapMethod(P, "getParameter", function (orig) {
    return function getParameter(p) {
      var v = orig.apply(this, arguments);
      if (v != null && p === 37445) { report("webgl"); return "Google Inc."; }                  // UNMASKED_VENDOR_WEBGL
      if (v != null && p === 37446) { report("webgl"); return "ANGLE (Generic Renderer)"; }   // UNMASKED_RENDERER_WEBGL
      return v;
    };
  });
  wrapMethod(P, "readPixels", function (orig) {
    return function readPixels(x, y, w, h, f, t, pixels) {
      var r = orig.apply(this, arguments);
      try { if (pixels && pixels.BYTES_PER_ELEMENT === 1 && pixels.length) { noiseBytes(pixels, "webgl"); report("webgl"); } } catch (e) { }
      return r;
    };
  });
});

// ---- audio -------------------------------------------------------------------------------------------------
var noised = new WeakSet();
var AB = g.AudioBuffer && g.AudioBuffer.prototype;
wrapMethod(AB, "getChannelData", function (orig) {
  return function getChannelData() {
    var arr = orig.apply(this, arguments);
    try { if (arr && !noised.has(arr)) { noiseFloat(arr, "audio", 1e-7); noised.add(arr); } report("audio"); } catch (e) { }
    return arr;
  };
});
wrapMethod(AB, "copyFromChannel", function (orig) {
  return function copyFromChannel(dest) {
    var r = orig.apply(this, arguments);
    try { if (dest && dest.length) { noiseFloat(dest, "audio", 1e-7); report("audio"); } } catch (e) { }
    return r;
  };
});
var AN = g.AnalyserNode && g.AnalyserNode.prototype;
["getFloatFrequencyData", "getFloatTimeDomainData"].forEach(function (m) {
  wrapMethod(AN, m, function (orig) {
    return function () { var r = orig.apply(this, arguments); try { if (arguments[0]) { noiseFloat(arguments[0], "analyser", 1e-6); report("audio"); } } catch (e) { } return r; };
  });
});
["getByteFrequencyData", "getByteTimeDomainData"].forEach(function (m) {
  wrapMethod(AN, m, function (orig) {
    return function () { var r = orig.apply(this, arguments); try { if (arguments[0]) { noiseBytes(arguments[0], "analyser"); report("audio"); } } catch (e) { } return r; };
  });
});

// ---- navigator and screen -------------------------------------------------------------------------------------
var NAV = g.Navigator && g.Navigator.prototype;
wrapGetter(NAV, "hardwareConcurrency", function (orig) { return function () { var v = orig.call(this); report("navigator"); return typeof v === "number" ? Math.min(v, 4) : v; }; });
wrapGetter(NAV, "deviceMemory", function (orig) { return function () { var v = orig.call(this); report("navigator"); return typeof v === "number" ? 8 : v; }; });
if (level === "strict") {
  wrapGetter(NAV, "languages", function (orig) { return function () { var v = orig.call(this); report("navigator"); return Array.isArray(v) || (v && v.length) ? Object.freeze([v[0]]) : v; }; });
  try { if (NAV && Object.getOwnPropertyDescriptor(NAV, "getBattery")) { var bd = Object.getOwnPropertyDescriptor(NAV, "getBattery"); bd.value = undefined; Object.defineProperty(NAV, "getBattery", bd); report("navigator"); } } catch (e) { }
}
var UAD = g.NavigatorUAData && g.NavigatorUAData.prototype;
wrapMethod(UAD, "getHighEntropyValues", function (orig) {
  return function getHighEntropyValues() {
    var p = orig.apply(this, arguments);
    return p.then(function (v) {
      report("navigator");
      var o = {};
      ["brands", "mobile", "platform"].forEach(function (k) { if (k in v) o[k] = v[k]; });
      if ("architecture" in v) o.architecture = ""; if ("bitness" in v) o.bitness = ""; if ("model" in v) o.model = "";
      if ("wow64" in v) o.wow64 = false; if ("platformVersion" in v) o.platformVersion = "10.0.0";
      if ("uaFullVersion" in v) o.uaFullVersion = String(v.uaFullVersion).split(".")[0] + ".0.0.0";
      if ("fullVersionList" in v) o.fullVersionList = (v.fullVersionList || []).map(function (b) { return { brand: b.brand, version: String(b.version).split(".")[0] + ".0.0.0" }; });
      return o;
    });
  };
});
if (level === "strict") {
  var SCR = g.Screen && g.Screen.prototype;
  function rounded(dim) { return function (orig) { return function () { var v = orig.call(this); report("screen"); var w = g[dim]; return typeof w === "number" && w > 0 ? Math.max(100, Math.round(w / 100) * 100) : v; }; }; }
  wrapGetter(SCR, "width", rounded("innerWidth")); wrapGetter(SCR, "availWidth", rounded("innerWidth"));
  wrapGetter(SCR, "height", rounded("innerHeight")); wrapGetter(SCR, "availHeight", rounded("innerHeight"));
  wrapGetter(SCR, "colorDepth", function (orig) { return function () { orig.call(this); return 24; }; });
  wrapGetter(SCR, "pixelDepth", function (orig) { return function () { orig.call(this); return 24; }; });
  var SS = g.SpeechSynthesis && g.SpeechSynthesis.prototype;
  wrapMethod(SS, "getVoices", function (orig) { return function getVoices() { orig.apply(this, arguments); report("other"); return []; }; });
}
