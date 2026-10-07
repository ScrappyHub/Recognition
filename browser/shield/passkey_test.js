// Recognition passkey self-test page script. Runs on http://localhost:<port>/ (a secure context where rpId "localhost" is valid).
// Exposes window.RecognitionPasskeyTest.run(env) -> Promise<Array<{name, ok, detail}>> so it can be driven by tests with a fake
// navigator.credentials. env = { navigator, crypto, location, TextEncoder, PublicKeyCredential } (defaults to the page globals).
// It creates one credential on the platform authenticator (Windows Hello / security key), then asks for an assertion and
// verifies the signature itself with WebCrypto. Nothing leaves the machine; the page sends no credential data anywhere.
(function (root) {
  "use strict";
  function b64u(buf) { var b = new Uint8Array(buf), s = ""; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function concat(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }
  function eq(a, b) { if (a.length !== b.length) return false; var d = 0; for (var i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }

  // ECDSA signatures from authenticators are ASN.1 DER; WebCrypto wants raw r||s.
  function derToRaw(der, size) {
    var d = new Uint8Array(der), p = 0;
    if (d[p++] !== 0x30) throw new Error("not a DER sequence");
    var len = d[p++]; if (len & 0x80) { var n = len & 0x7f; len = 0; while (n--) len = (len << 8) | d[p++]; }
    function readInt() {
      if (d[p++] !== 0x02) throw new Error("not a DER integer");
      var l = d[p++], v = d.slice(p, p + l); p += l;
      while (v.length > size && v[0] === 0) v = v.slice(1);
      if (v.length > size) throw new Error("integer too long");
      var o = new Uint8Array(size); o.set(v, size - v.length); return o;
    }
    var r = readInt(), s = readInt(); return concat(r, s);
  }

  async function run(env) {
    env = env || {};
    var nav = env.navigator || root.navigator, cr = env.crypto || root.crypto, loc = env.location || root.location;
    var PKC = env.PublicKeyCredential || root.PublicKeyCredential;
    var enc = new (env.TextEncoder || root.TextEncoder)();
    var results = [];
    function add(name, ok, detail) { results.push({ name: name, ok: !!ok, detail: detail || "" }); }

    add("secure context (localhost)", (env.isSecureContext !== undefined ? env.isSecureContext : root.isSecureContext) === true, loc.origin);
    add("WebAuthn available", !!(PKC && nav.credentials && nav.credentials.create), PKC ? "PublicKeyCredential present" : "PublicKeyCredential missing");
    if (!PKC || !nav.credentials) return results;
    try { var uvpa = await PKC.isUserVerifyingPlatformAuthenticatorAvailable(); add("Windows Hello / platform authenticator", uvpa, uvpa ? "available" : "not available (a security key can still work)"); } catch (e) { add("Windows Hello / platform authenticator", false, String(e && e.message || e)); }
    try { var cm = PKC.isConditionalMediationAvailable ? await PKC.isConditionalMediationAvailable() : false; add("autofill (conditional UI)", cm, cm ? "available" : "not available"); } catch (e2) { add("autofill (conditional UI)", false, "unknown"); }

    var challenge = cr.getRandomValues(new Uint8Array(32)), userId = cr.getRandomValues(new Uint8Array(16));
    var cred;
    try {
      cred = await nav.credentials.create({ publicKey: {
        rp: { name: "Recognition passkey test", id: loc.hostname }, user: { id: userId, name: "recognition-test", displayName: "Recognition test" },
        challenge: challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { residentKey: "discouraged", userVerification: "preferred" }, attestation: "none", timeout: 120000 } });
    } catch (e3) { add("create a passkey", false, (e3 && e3.name ? e3.name + ": " : "") + (e3 && e3.message || "")); return results; }
    if (!cred) { add("create a passkey", false, "no credential returned"); return results; }
    var cd = JSON.parse(new TextDecoder().decode(cred.response.clientDataJSON));
    var okCreate = cd.type === "webauthn.create" && cd.challenge === b64u(challenge) && cd.origin === loc.origin;
    add("create a passkey", okCreate, okCreate ? "credential created; challenge and origin verified" : "client data did not match (type " + cd.type + ", origin " + cd.origin + ")");
    if (!okCreate) return results;

    var spki = cred.response.getPublicKey && cred.response.getPublicKey(); var alg = cred.response.getPublicKeyAlgorithm && cred.response.getPublicKeyAlgorithm();
    if (!spki) { add("read public key", false, "authenticator did not expose the public key"); return results; }
    add("read public key", true, "algorithm " + alg);

    var challenge2 = cr.getRandomValues(new Uint8Array(32)), asr;
    try {
      asr = await nav.credentials.get({ publicKey: { challenge: challenge2, rpId: loc.hostname, allowCredentials: [{ type: "public-key", id: cred.rawId }], userVerification: "preferred", timeout: 120000 } });
    } catch (e4) { add("sign in with the passkey", false, (e4 && e4.name ? e4.name + ": " : "") + (e4 && e4.message || "")); return results; }
    var cd2 = JSON.parse(new TextDecoder().decode(asr.response.clientDataJSON));
    var okCd = cd2.type === "webauthn.get" && cd2.challenge === b64u(challenge2) && cd2.origin === loc.origin;
    add("assertion client data", okCd, okCd ? "challenge and origin verified" : "mismatch");
    var authData = new Uint8Array(asr.response.authenticatorData);
    var rpHash = new Uint8Array(await cr.subtle.digest("SHA-256", enc.encode(loc.hostname)));
    add("relying-party hash", eq(authData.slice(0, 32), rpHash), "authenticator bound the credential to " + loc.hostname);
    add("user presence flag", (authData[32] & 1) === 1, (authData[32] & 4) ? "user verified (PIN/biometric)" : "touch only");
    var signed = concat(authData, new Uint8Array(await cr.subtle.digest("SHA-256", asr.response.clientDataJSON)));
    var sigOk = false, why = "";
    try {
      if (alg === -7) {
        var k = await cr.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
        sigOk = await cr.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k, derToRaw(asr.response.signature, 32), signed);
      } else if (alg === -257) {
        var k2 = await cr.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
        sigOk = await cr.subtle.verify("RSASSA-PKCS1-v1_5", k2, asr.response.signature, signed);
      } else why = "unsupported algorithm " + alg;
    } catch (e5) { why = String(e5 && e5.message || e5); }
    add("signature verifies", sigOk, sigOk ? "signature checked against the public key" : (why || "signature did not verify"));
    return results;
  }
  root.RecognitionPasskeyTest = { run: run, derToRaw: derToRaw, b64u: b64u };
})(typeof globalThis !== "undefined" ? globalThis : this);
