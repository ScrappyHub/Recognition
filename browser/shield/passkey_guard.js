// Recognition passkey guard. Body of a function (g, __cfg) injected into every web frame before page scripts run.
//   __cfg { tel: "<hex>", level: "on|off", sites: { "<host or registrable domain>": "on|off" }, suffixes: [...] }
// What it does:
//  - counts navigator.credentials.create/get calls that use "publicKey" (WebAuthn / passkeys). Only the KIND is counted, never
//    challenges, ids or any credential data. The host reads and resets the counter through a non-enumerable window property.
//  - when passkeys are switched off for the site: the call is rejected with NotAllowedError (exactly what a user cancelling
//    produces), and the capability probes answer "no", so sites fall back to their password form.
//  - it never touches credential data and never calls the authenticator itself; creation and signing stay with Windows.
// Not covered: workers (no WebAuthn there anyway).
"use strict";
if (!__cfg || typeof __cfg.tel !== "string" || __cfg.tel.length < 16) return;
if (!g.location || (g.location.protocol !== "https:" && g.location.protocol !== "http:")) return;

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
  } catch (e) { }
  return g.location.hostname;
}
var host = topHost(), site = registrable(host), sites = __cfg.sites || {};
var has = Object.prototype.hasOwnProperty;
var setting = has.call(sites, host) ? sites[host] : has.call(sites, site) ? sites[site] : __cfg.level;
var blocked = setting === "off";

var counts = {};
function report(k) { counts[k] = (counts[k] || 0) + 1; }
try {
  Object.defineProperty(g, "__rc_" + __cfg.tel, {
    value: function () { var out = []; for (var k in counts) out.push(k + "=" + counts[k]); counts = {}; return out.join(","); },
    enumerable: false, configurable: false, writable: false
  });
} catch (e) { }

var natives = new WeakMap();
var origToString = g.Function.prototype.toString;
function nativeText(fn) { try { return origToString.call(fn); } catch (e) { return "function () { [native code] }"; } }
function wrap(obj, name, make) {
  try {
    var d = obj && Object.getOwnPropertyDescriptor(obj, name);
    if (!d || typeof d.value !== "function") return;
    var orig = d.value, w = make(orig);
    try { Object.defineProperty(w, "name", { value: name, configurable: true }); } catch (e) { }
    try { Object.defineProperty(w, "length", { value: orig.length, configurable: true }); } catch (e) { }
    natives.set(w, nativeText(orig));
    d.value = w; Object.defineProperty(obj, name, d);
  } catch (e) { }
}
var curToString = g.Function.prototype.toString;
try {
  var fts = function toString() { return natives.has(this) ? natives.get(this) : curToString.call(this); };
  natives.set(fts, nativeText(curToString));
  var dts = Object.getOwnPropertyDescriptor(g.Function.prototype, "toString"); dts.value = fts;
  Object.defineProperty(g.Function.prototype, "toString", dts);
} catch (e) { }

function denied() { return new g.DOMException("The operation either timed out or was not allowed.", "NotAllowedError"); }
var CC = g.CredentialsContainer && g.CredentialsContainer.prototype;
["create", "get"].forEach(function (m) {
  wrap(CC, m, function (orig) {
    return function () {
      var o = arguments[0];
      if (o && typeof o === "object" && o.publicKey) {
        report(m === "create" ? "pk_create" : "pk_get");
        if (blocked) return g.Promise.reject(denied());
      }
      return orig.apply(this, arguments);
    };
  });
});
if (blocked) {
  var PKC = g.PublicKeyCredential;
  ["isUserVerifyingPlatformAuthenticatorAvailable", "isConditionalMediationAvailable"].forEach(function (m) {
    wrap(PKC, m, function () { return function () { return g.Promise.resolve(false); }; });
  });
}
