// Node test for fingerprint_shield.js using a fake global. Run: node shield.test.js
const fs=require('fs'),path=require('path');
const src=fs.readFileSync(path.join(__dirname,'..','..','browser','shield','fingerprint_shield.js'),'utf8');
let pass=0,fail=0; const ck=(c,l)=>{ if(c)pass++; else {fail++; console.log('FAIL: '+l);} };

function makeGlobal(host,top=true){
  const g={Function,Object,Array,WeakMap,WeakSet,Math,String,Number};
  g.self=g; g.top=top?g:{}; g.location={hostname:host,protocol:'https:',ancestorOrigins:[]}; g.URL=URL;
  g.document={referrer:'',createElement:()=>{ const o=Object.create(g.HTMLCanvasElement.prototype); let w=0,h=0; Object.defineProperty(o,'width',{get:()=>w,set:v=>{w=v;o._px=new Uint8ClampedArray(w*h*4);}}); Object.defineProperty(o,'height',{get:()=>h,set:v=>{h=v;o._px=new Uint8ClampedArray(w*h*4);}}); return o; }};
  g.setTimeout=(f)=>0;
  function makeCanvas(w,h){ return {width:w,height:h,_px:new Uint8ClampedArray(w*h*4).fill(100)}; }
  g.HTMLCanvasElement=function(){}; 
  g.HTMLCanvasElement.prototype={
    getContext(){ const c=this; return {drawImage(s){ c._px.set(s._px.subarray(0,c._px.length)); }, getImageData(x,y,w,h){return {data:new Uint8ClampedArray(c._px),width:w,height:h};}, putImageData(img){ c._px.set(img.data); } }; },
    toDataURL(){ let s=0; for(const v of this._px)s=(s*31+v)>>>0; return 'data:'+s; },
    toBlob(){}
  };
  g.CanvasRenderingContext2D=function(){};
  g.CanvasRenderingContext2D.prototype={ getImageData(x,y,w,h){ return {data:new Uint8ClampedArray(w*h*4).fill(100),width:w,height:h}; } };
  g.AudioBuffer=function(){}; g.AudioBuffer.prototype={ getChannelData(){ return new Float32Array(44100).fill(0.5);} };
  g.Navigator=function(){}; Object.defineProperty(g.Navigator.prototype,'hardwareConcurrency',{get(){return 32},configurable:true});
  Object.defineProperty(g.Navigator.prototype,'deviceMemory',{get(){return 16},configurable:true});
  g.WebGLRenderingContext=function(){}; g.WebGLRenderingContext.prototype={getParameter(p){return p===37446?'NVIDIA RTX 4090':'x';}, readPixels(x,y,w,h,f,t,px){ px.fill(50);} };
  g.makeCanvas=makeCanvas; g.chrome={webview:{postMessage(){}}};
  return g;
}
function inject(g,cfg){ new Function('g','__cfg',src)(g,cfg); }
const cfg=(o={})=>Object.assign({key:'aabbccddeeff0011aabbccddeeff0011',tel:'1122334455667788',level:'standard',sites:{},suffixes:['co.uk']},o);

// canvas readbacks perturbed, deterministic per site+key
let g1=makeGlobal('a.example.com'); inject(g1,cfg());
const c1=g1.makeCanvas(300,150);
const d1=g1.HTMLCanvasElement.prototype.toDataURL.call(c1);
const d1b=g1.HTMLCanvasElement.prototype.toDataURL.call(c1);
let gOrig=makeGlobal('a.example.com'); const dOrig=gOrig.HTMLCanvasElement.prototype.toDataURL.call(gOrig.makeCanvas(300,150));
ck(d1!==dOrig,'canvas output differs from unshielded');
ck(d1===d1b,'canvas noise stable within a site/session');
let g2=makeGlobal('other.org'); inject(g2,cfg());
ck(g2.HTMLCanvasElement.prototype.toDataURL.call(g2.makeCanvas(300,150))!==d1,'different site -> different canvas hash');
let g3=makeGlobal('a.example.com'); inject(g3,cfg({key:'99887766aabbccdd99887766aabbccdd'}));
ck(g3.HTMLCanvasElement.prototype.toDataURL.call(g3.makeCanvas(300,150))!==d1,'different session key -> different hash');
let g4=makeGlobal('b.example.com'); inject(g4,cfg());
ck(g4.HTMLCanvasElement.prototype.toDataURL.call(g4.makeCanvas(300,150))===d1,'subdomains of one registrable domain share noise');
let g5=makeGlobal('x.foo.co.uk'),g6=makeGlobal('x.bar.co.uk'); inject(g5,cfg()); inject(g6,cfg());
ck(g5.HTMLCanvasElement.prototype.toDataURL.call(g5.makeCanvas(300,150))!==g6.HTMLCanvasElement.prototype.toDataURL.call(g6.makeCanvas(300,150)),'public suffix co.uk respected');
// getImageData
const id=g1.CanvasRenderingContext2D.prototype.getImageData(0,0,100,100);
let changed=0,alphaChanged=0,maxDelta=0; for(let i=0;i<id.data.length;i++){ const dv=Math.abs(id.data[i]-100); if(dv){ changed++; if(i%4===3)alphaChanged++; maxDelta=Math.max(maxDelta,dv);} }
ck(changed>0,'getImageData perturbed'); ck(alphaChanged===0,'alpha untouched'); ck(maxDelta<=1,'noise is +/-1 only');
// webgl
ck(g1.WebGLRenderingContext.prototype.getParameter(37446)==='ANGLE (Generic Renderer)','webgl renderer masked');
ck(g1.WebGLRenderingContext.prototype.getParameter(1)==='x','other webgl params untouched');
const px=new Uint8Array(100000); g1.WebGLRenderingContext.prototype.readPixels(0,0,1,1,0,0,px); ck(px.some(v=>v!==50),'readPixels noised');
// audio
const ch=g1.AudioBuffer.prototype.getChannelData(); ck(ch.some(v=>v!==0.5),'audio noised'); ck(ch.every(v=>Math.abs(v-0.5)<1e-5),'audio noise tiny');
// navigator
const nd=Object.getOwnPropertyDescriptor(g1.Navigator.prototype,'hardwareConcurrency').get.call({});
ck(nd===4,'hardwareConcurrency capped'); ck(Object.getOwnPropertyDescriptor(g1.Navigator.prototype,'deviceMemory').get.call({})===8,'deviceMemory fixed');
// native-looking
const fn=g1.HTMLCanvasElement.prototype.toDataURL;
ck(fn.name==='toDataURL','name preserved'); ck(Function.prototype.toString.call(fn)===Function.prototype.toString.call(gOrig.HTMLCanvasElement.prototype.toDataURL),'toString matches original');
// off + exempt
let go=makeGlobal('a.example.com'); inject(go,cfg({level:'off'}));
ck(go.HTMLCanvasElement.prototype.toDataURL.call(go.makeCanvas(300,150))===dOrig,'level off leaves canvas alone');
let ge=makeGlobal('a.example.com'); inject(ge,cfg({sites:{'example.com':'off'}}));
ck(ge.HTMLCanvasElement.prototype.toDataURL.call(ge.makeCanvas(300,150))===dOrig,'exempt site untouched');
// strict
let gs=makeGlobal('a.example.com'); inject(gs,cfg({level:'strict'}));
ck(Object.getOwnPropertyDescriptor(gs.Navigator.prototype,'hardwareConcurrency').get.call({})===4,'strict still works');
// telemetry via hidden property, never postMessage
let posted=0; g1.chrome.webview.postMessage=()=>{posted++};
const tf=g1['__rc_1122334455667788']; ck(typeof tf==='function','telemetry accessor exists');
const tel=tf(); ck(/canvas=\d+/.test(tel)&&/webgl=\d+/.test(tel),'telemetry has counts: '+tel); ck(tf()==='','telemetry resets after read'); ck(posted===0,'no postMessage used');
ck(!Object.keys(g1).includes('__rc_1122334455667788'),'accessor not enumerable');
// per-site strict override on a standard default
let gp=makeGlobal('strict.example.net'); inject(gp,cfg({sites:{'example.net':'strict'}})); ck(typeof gp['__rc_1122334455667788']==='function','per-site override applies');
// bad level / short key do nothing
let gb=makeGlobal('a.example.com'); inject(gb,cfg({level:'bogus'})); ck(gb.HTMLCanvasElement.prototype.toDataURL.call(gb.makeCanvas(300,150))===dOrig,'unknown level -> no-op');
let gk=makeGlobal('a.example.com'); inject(gk,cfg({key:'x'})); ck(gk.HTMLCanvasElement.prototype.toDataURL.call(gk.makeCanvas(300,150))===dOrig,'short key -> no-op');
// internal / data pages are never touched
let gi=makeGlobal('a.example.com'); gi.location.protocol='data:'; inject(gi,cfg()); ck(gi.HTMLCanvasElement.prototype.toDataURL.call(gi.makeCanvas(300,150))===dOrig,'data: page untouched');
let gf=makeGlobal(''); gf.location.protocol='file:'; inject(gf,cfg()); ck(gf.HTMLCanvasElement.prototype.toDataURL.call(gf.makeCanvas(300,150))===dOrig,'file: page untouched');
// resilience: missing APIs must not throw
try{ const e={Function,Object,Array,WeakMap,WeakSet,Math,String,Number,location:{hostname:'x.com',protocol:'https:'},URL,document:{referrer:''}}; e.self=e;e.top=e; new Function('g','__cfg',src)(e,cfg()); ck(true,'no throw on bare global'); }catch(x){ ck(false,'threw on bare global '+x); }
// tiny canvas / zero size
try{ const z=g1.makeCanvas(0,0); g1.HTMLCanvasElement.prototype.toDataURL.call(z); ck(true,'zero-size canvas ok'); }catch(x){ ck(false,'zero canvas threw '+x);} 
// cannot be fed a hostile cfg
try{ new Function('g','__cfg',src)(makeGlobal('x.com'),null); ck(true,'null cfg ok'); }catch(x){ ck(false,'null cfg threw'); }
console.log(`shield: ${pass} passed, ${fail} failed`); process.exit(fail?1:0);
