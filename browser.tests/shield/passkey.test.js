// node passkey.test.js : tests passkey_guard.js and passkey_test.js against a simulated authenticator.
const fs=require('fs'),path=require('path'),{webcrypto}=require('crypto');
const root=path.join(__dirname,'..','..','browser','shield');
const guardSrc=fs.readFileSync(path.join(root,'passkey_guard.js'),'utf8');
let pass=0,fail=0; const ck=(c,l)=>{ if(c)pass++; else {fail++; console.log('FAIL: '+l);} };

// ---- guard ----
function makeG(host){
  const g={Function,Object,Array,WeakMap,Promise,String,Number}; g.self=g; g.top=g;
  g.location={hostname:host,protocol:'https:',ancestorOrigins:[]}; g.URL=URL;
  g.DOMException=DOMException;
  g.CredentialsContainer=function(){}; g.CredentialsContainer.prototype={ create(o){return Promise.resolve({made:true})}, get(o){return Promise.resolve({got:true})} };
  g.PublicKeyCredential=function(){}; g.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable=()=>Promise.resolve(true); g.PublicKeyCredential.isConditionalMediationAvailable=()=>Promise.resolve(true);
  return g;
}
const inj=(g,cfg)=>new Function('g','__cfg',guardSrc)(g,cfg);
const cfg=(o={})=>Object.assign({tel:'0011223344556677',level:'on',sites:{},suffixes:['co.uk']},o);
(async()=>{
  let g=makeG('login.example.com'); inj(g,cfg());
  const P=g.CredentialsContainer.prototype;
  ck((await P.create({publicKey:{}})).made===true,'create passes through when passkeys on');
  ck((await P.get({publicKey:{}})).got===true,'get passes through');
  ck((await P.get({password:true})).got===true,'non-publicKey get untouched');
  const tel=g['__rc_0011223344556677'](); ck(tel==='pk_create=1,pk_get=1',"counts only publicKey calls: "+tel);
  ck(g['__rc_0011223344556677']()==='','counter resets');
  ck(!Object.keys(g).includes('__rc_0011223344556677'),'accessor not enumerable');
  ck(P.create.name==='create'&&Function.prototype.toString.call(P.create)===Function.prototype.toString.call(makeG('x').CredentialsContainer.prototype.create),'native-looking');
  // off for site
  let g2=makeG('login.example.com'); inj(g2,cfg({sites:{'example.com':'off'}}));
  let err=null; try{ await g2.CredentialsContainer.prototype.create({publicKey:{}}); }catch(e){err=e;}
  ck(err&&err.name==='NotAllowedError','blocked create -> NotAllowedError');
  err=null; try{ await g2.CredentialsContainer.prototype.get({publicKey:{}}); }catch(e){err=e;} ck(err&&err.name==='NotAllowedError','blocked get -> NotAllowedError');
  ck((await g2.CredentialsContainer.prototype.get({password:true})).got===true,'blocked site still allows password credentials');
  ck(await g2.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()===false,'probe says no when blocked');
  ck(await g2.PublicKeyCredential.isConditionalMediationAvailable()===false,'conditional probe says no when blocked');
  ck(g2['__rc_0011223344556677']()==='pk_create=1,pk_get=1','blocked attempts still counted');
  // other site unaffected
  let g3=makeG('other.org'); inj(g3,cfg({sites:{'example.com':'off'}})); ck((await g3.CredentialsContainer.prototype.create({publicKey:{}})).made===true,'other site unaffected');
  // global off
  let g4=makeG('other.org'); inj(g4,cfg({level:'off'})); err=null; try{ await g4.CredentialsContainer.prototype.create({publicKey:{}}); }catch(e){err=e;} ck(err&&err.name==='NotAllowedError','global off blocks');
  let g5=makeG('x.com'); g5.location.protocol='data:'; inj(g5,cfg({level:'off'})); ck((await g5.CredentialsContainer.prototype.create({publicKey:{}})).made===true,'data: page untouched');
  try{ new Function('g','__cfg',guardSrc)({Function,Object,Array,WeakMap,location:{hostname:'a',protocol:'https:'}},cfg()); ck(true,'bare global ok'); }catch(e){ ck(false,'bare global threw '+e); }

  // ---- test page script with a simulated authenticator ----
  require(path.join(root,'passkey_test.js'));
  const T=globalThis.RecognitionPasskeyTest;
  ck(T&&typeof T.run==='function','test script exposes run');
  const sub=webcrypto.subtle, origin='http://localhost:51234', rp='localhost';
  function rawToDer(raw){ const h=raw.length/2; const f=a=>{ let v=Array.from(a); while(v.length>1&&v[0]===0)v.shift(); if(v[0]&0x80)v.unshift(0); return [0x02,v.length,...v]; }; const r=f(raw.slice(0,h)),s=f(raw.slice(h)); const body=[...r,...s]; return Uint8Array.from([0x30,body.length,...body]); }
  async function makeEnv(opts={}){
    const kp=await sub.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']); const spki=new Uint8Array(await sub.exportKey('spki',kp.publicKey));
    const rawId=webcrypto.getRandomValues(new Uint8Array(16)); const te=new TextEncoder();
    const env={ isSecureContext:true, location:{hostname:rp,origin}, crypto:webcrypto, TextEncoder,
      PublicKeyCredential:{ isUserVerifyingPlatformAuthenticatorAvailable:async()=>true, isConditionalMediationAvailable:async()=>false },
      navigator:{ credentials:{
        async create({publicKey}){ if(opts.denyCreate) throw new DOMException('cancelled','NotAllowedError');
          const cd=te.encode(JSON.stringify({type:'webauthn.create',challenge:Buffer.from(publicKey.challenge).toString('base64url'),origin:opts.badOrigin?'http://evil.test':origin}));
          return {rawId:rawId.buffer,response:{clientDataJSON:cd.buffer,getPublicKey:()=>spki.buffer,getPublicKeyAlgorithm:()=>-7}}; },
        async get({publicKey}){
          const cd=te.encode(JSON.stringify({type:'webauthn.get',challenge:Buffer.from(publicKey.challenge).toString('base64url'),origin}));
          const rpHash=new Uint8Array(await sub.digest('SHA-256',te.encode(opts.wrongRp?'evil.test':rp)));
          const ad=new Uint8Array(37); ad.set(rpHash,0); ad[32]=0x05; ad[36]=1;
          const cdh=new Uint8Array(await sub.digest('SHA-256',cd)); const msg=new Uint8Array(ad.length+cdh.length); msg.set(ad,0); msg.set(cdh,ad.length);
          let sigRaw=new Uint8Array(await sub.sign({name:'ECDSA',hash:'SHA-256'},kp.privateKey,msg)); if(opts.badSig) sigRaw[5]^=0xff;
          return {response:{clientDataJSON:cd.buffer,authenticatorData:ad.buffer,signature:rawToDer(sigRaw).buffer}}; } } } };
    return env;
  }
  let r=await T.run(await makeEnv()); ck(r.every(x=>x.ok||x.name.startsWith('autofill')),'good authenticator: all checks pass '+JSON.stringify(r.filter(x=>!x.ok)));
  ck(r.some(x=>x.name==='signature verifies'&&x.ok),'signature check ran and passed');
  r=await T.run(await makeEnv({badSig:true})); ck(r.some(x=>x.name==='signature verifies'&&!x.ok),'tampered signature is detected');
  r=await T.run(await makeEnv({wrongRp:true})); ck(r.some(x=>x.name==='relying-party hash'&&!x.ok),'wrong rp hash is detected');
  r=await T.run(await makeEnv({badOrigin:true})); ck(r.some(x=>x.name==='create a passkey'&&!x.ok),'wrong origin in client data is detected');
  r=await T.run(await makeEnv({denyCreate:true})); ck(r.some(x=>x.name==='create a passkey'&&!x.ok&&/NotAllowedError/.test(x.detail)),'user cancel reported');
  r=await T.run({isSecureContext:true,location:{hostname:rp,origin},crypto:webcrypto,TextEncoder,navigator:{},PublicKeyCredential:undefined}); ck(r.some(x=>x.name==='WebAuthn available'&&!x.ok),'missing WebAuthn reported without throwing');
  // DER parser edge cases
  const d=T.derToRaw(Uint8Array.from([0x30,0x08,0x02,0x02,0x00,0x80,0x02,0x02,0x01,0x02]).buffer,32); ck(d.length===64&&d[31]===0x80&&d[63]===0x02&&d[62]===0x01,'DER->raw handles leading zero and padding');
  let thrown=false; try{T.derToRaw(Uint8Array.from([0x31,0,0]).buffer,32);}catch(e){thrown=true;} ck(thrown,'DER parser rejects garbage');
  console.log(`passkey: ${pass} passed, ${fail} failed`); process.exit(fail?1:0);
})();
