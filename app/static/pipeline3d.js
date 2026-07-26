/* Securo pipeline3d — orbital agent scene, shared by index.html (embedded
   panel) and mesh-lab.html (fullscreen lab). All HUD elements are OPTIONAL:
   the engine looks them up by id and skips whatever the host page lacks.
   Central reactor = live health score; agent satellites orbit it; the active
   agent is derived from the REAL execution log; urgent findings appear as
   red shards. Click an agent to fly the camera to it. */
import * as THREE from '/vendor/three/three.module.js';
import { EffectComposer } from '/vendor/three/addons/postprocessing/EffectComposer.js';
import { RenderPass }     from '/vendor/three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass }from '/vendor/three/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass }     from '/vendor/three/addons/postprocessing/OutputPass.js';

const AGENTS = ["المنسّق","صائد التهديدات","مدقق الأصول","المعالجة"];
const KEYS   = ["Orchestrator","Threat Hunter","Asset Auditor","Remediation"]; // server log tags
const DESC   = [
  "يدير خط الفحص كاملاً: يستدعي بقية الوكلاء بالترتيب ويجمع نتائجهم في التقرير النهائي.",
  "يطابق كل برنامج مثبّت مع قاعدة ثغرات NVD الرسمية ويحدد درجة الخطورة لكل تطابق.",
  "يجرد البرامج المثبّتة عبر winget، يستبعد الألعاب وحزم التعريفات، ويثبت أرقام الإصدارات.",
  "يحوّل النتائج الخام إلى توصيات قابلة للتنفيذ ويميّز ما يحتاج تحديثاً عاجلاً.",
];
const COL = [0xa855f7, 0x22d3ee, 0xf5a524, 0x3ddc84];
const CSS = ["#a855f7", "#22d3ee", "#f5a524", "#3ddc84"];

const $ = id => document.getElementById(id);
const canvas = $('p3d');
if (canvas) init();

function init(){

const state = { active:-1, doneUpTo:0, health:null, urgent:0, total:0,
                live:false, demo:false, selected:-1 };

const NOISE = `
vec3 mod289(vec3 x){return x-floor(x*(1.0/289.0))*289.0;}
vec4 mod289(vec4 x){return x-floor(x*(1.0/289.0))*289.0;}
vec4 permute(vec4 x){return mod289(((x*34.0)+1.0)*x);}
vec4 taylorInvSqrt(vec4 r){return 1.79284291400159-0.85373472095314*r;}
float snoise(vec3 v){
  const vec2 C=vec2(1.0/6.0,1.0/3.0); const vec4 D=vec4(0.0,0.5,1.0,2.0);
  vec3 i=floor(v+dot(v,C.yyy)); vec3 x0=v-i+dot(i,C.xxx);
  vec3 g=step(x0.yzx,x0.xyz); vec3 l=1.0-g; vec3 i1=min(g.xyz,l.zxy); vec3 i2=max(g.xyz,l.zxy);
  vec3 x1=x0-i1+C.xxx; vec3 x2=x0-i2+C.yyy; vec3 x3=x0-D.yyy;
  i=mod289(i);
  vec4 p=permute(permute(permute(i.z+vec4(0.0,i1.z,i2.z,1.0))+i.y+vec4(0.0,i1.y,i2.y,1.0))+i.x+vec4(0.0,i1.x,i2.x,1.0));
  float n_=0.142857142857; vec3 ns=n_*D.wyz-D.xzx;
  vec4 j=p-49.0*floor(p*ns.z*ns.z);
  vec4 x_=floor(j*ns.z); vec4 y_=floor(j-7.0*x_);
  vec4 x=x_*ns.x+ns.yyyy; vec4 y=y_*ns.x+ns.yyyy; vec4 h=1.0-abs(x)-abs(y);
  vec4 b0=vec4(x.xy,y.xy); vec4 b1=vec4(x.zw,y.zw);
  vec4 s0=floor(b0)*2.0+1.0; vec4 s1=floor(b1)*2.0+1.0; vec4 sh=-step(h,vec4(0.0));
  vec4 a0=b0.xzyw+s0.xzyw*sh.xxyy; vec4 a1=b1.xzyw+s1.xzyw*sh.zzww;
  vec3 p0=vec3(a0.xy,h.x); vec3 p1=vec3(a0.zw,h.y); vec3 p2=vec3(a1.xy,h.z); vec3 p3=vec3(a1.zw,h.w);
  vec4 norm=taylorInvSqrt(vec4(dot(p0,p0),dot(p1,p1),dot(p2,p2),dot(p3,p3)));
  p0*=norm.x;p1*=norm.y;p2*=norm.z;p3*=norm.w;
  vec4 m=max(0.6-vec4(dot(x0,x0),dot(x1,x1),dot(x2,x2),dot(x3,x3)),0.0); m=m*m;
  return 42.0*dot(m*m,vec4(dot(p0,x0),dot(p1,x1),dot(p2,x2),dot(p3,x3)));
}`;

/* ---------- renderer / composer ---------- */
const renderer = new THREE.WebGLRenderer({ canvas, antialias:true, alpha:true });
renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 1.5));
renderer.toneMapping = THREE.ACESFilmicToneMapping;
// dialled down from the lab version — the glow was blinding at scan time
renderer.toneMappingExposure = 0.88;

const scene = new THREE.Scene();
scene.fog = new THREE.FogExp2(0x05030a, 0.03);
const camera = new THREE.PerspectiveCamera(50, 1, .1, 120);

const composer = new EffectComposer(renderer);
composer.addPass(new RenderPass(scene, camera));
const bloom = new UnrealBloomPass(new THREE.Vector2(1,1), 0.5, 0.5, 0.22);
composer.addPass(bloom);
composer.addPass(new OutputPass());

function resize(){
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return;
  renderer.setSize(w, h, false);
  composer.setSize(w, h);
  bloom.resolution.set(w/2, h/2); // half-res bloom: visually identical, 4x cheaper
  camera.aspect = w / h; camera.updateProjectionMatrix();
}
new ResizeObserver(resize).observe(canvas);
addEventListener('resize', resize); resize();

/* ---------- calm space backdrop: distant starfield ---------- */
const SN = 900, sPos = new Float32Array(SN*3), sSeed = new Float32Array(SN);
for (let i = 0; i < SN; i++){
  // points on a far shell so they never intersect the scene
  const r = 34 + Math.random()*26, th = Math.random()*Math.PI*2, ph = Math.acos(Math.random()*2-1);
  sPos[i*3]   = r*Math.sin(ph)*Math.cos(th);
  sPos[i*3+1] = r*Math.cos(ph)*.6;
  sPos[i*3+2] = r*Math.sin(ph)*Math.sin(th);
  sSeed[i] = Math.random()*10;
}
const sGeo = new THREE.BufferGeometry();
sGeo.setAttribute('position', new THREE.BufferAttribute(sPos,3));
sGeo.setAttribute('aSeed', new THREE.BufferAttribute(sSeed,1));
const starMat = new THREE.ShaderMaterial({
  transparent:true, blending:THREE.AdditiveBlending, depthWrite:false, fog:false,
  uniforms:{ uTime:{value:0} },
  vertexShader:`attribute float aSeed; varying float vA; varying float vSeed; uniform float uTime;
    void main(){
      vSeed=aSeed;
      vA=.35+.3*sin(uTime*(.4+fract(aSeed)*.5)+aSeed*7.0); // slow gentle twinkle
      vec4 mv=modelViewMatrix*vec4(position,1.0);
      gl_PointSize=(1.2+fract(aSeed*3.7)*1.6)*(38./-mv.z);
      gl_Position=projectionMatrix*mv; }`,
  fragmentShader:`varying float vA; varying float vSeed;
    void main(){
      vec2 c=gl_PointCoord-.5; float d=length(c); if(d>.5) discard;
      // subtle colour cast: most stars white, some violet / ice-blue
      vec3 tint = mix(vec3(1.0), mix(vec3(.75,.62,1.0), vec3(.6,.8,1.0), step(.5,fract(vSeed*1.3))), .4*step(.6,fract(vSeed*2.1)));
      gl_FragColor=vec4(tint, vA*smoothstep(.5,0.,d)); }`
});
scene.add(new THREE.Points(sGeo, starMat));

/* ---------- reactor core (health) ---------- */
const coreMat = new THREE.ShaderMaterial({
  transparent:true, blending:THREE.AdditiveBlending, depthWrite:false,
  uniforms:{ uTime:{value:0}, uCol:{value:new THREE.Color(0x7c3aed)}, uBeat:{value:0} },
  vertexShader: NOISE + `
    uniform float uTime; uniform float uBeat;
    varying vec3 vN; varying vec3 vP; varying float vD;
    void main(){
      float d = snoise(normal*2.2 + uTime*.45) * (0.10 + uBeat*0.14);
      vec3 p = position + normal*d;
      vD = d;
      vN = normalize(normalMatrix*normal);
      vec4 mv = modelViewMatrix*vec4(p,1.0); vP = mv.xyz;
      gl_Position = projectionMatrix*mv;
    }`,
  fragmentShader:`
    uniform vec3 uCol; uniform float uTime;
    varying vec3 vN; varying vec3 vP; varying float vD;
    void main(){
      vec3 V = normalize(-vP);
      float fres = pow(1.0-max(dot(vN,V),0.0), 2.0);
      float vein = smoothstep(.02,.09, vD);
      vec3 col = uCol*(0.65 + fres*1.25 + vein*1.5);
      gl_FragColor = vec4(col, 0.18 + fres*0.6 + vein*0.28);
    }`
});
const core = new THREE.Mesh(new THREE.IcosahedronGeometry(1.15, 5), coreMat);
scene.add(core);
const heart = new THREE.Mesh(new THREE.SphereGeometry(.38, 24, 24),
  new THREE.MeshBasicMaterial({ color:0xffffff, transparent:true, opacity:.5,
    blending:THREE.AdditiveBlending, depthWrite:false }));
scene.add(heart);
const coreRings = [];
[1.7, 2.05].forEach((r, k) => {
  const ring = new THREE.Mesh(new THREE.TorusGeometry(r, .016, 8, 128),
    new THREE.MeshBasicMaterial({ color:0xa855f7, transparent:true, opacity:.26,
      blending:THREE.AdditiveBlending, depthWrite:false }));
  ring.rotation.x = Math.PI/2 + (k ? .28 : -.18);
  scene.add(ring); coreRings.push(ring);
});

/* ---------- agent satellites (gyroscope style) ---------- */
const ORBIT_R = 4.6;
const P = AGENTS.map((_, i) => {
  const a = (i / AGENTS.length) * Math.PI*2 + Math.PI/4;
  return new THREE.Vector3(Math.cos(a)*ORBIT_R, Math.sin(i*2.1)*.55, Math.sin(a)*ORBIT_R);
});
const shellMat = hex => new THREE.ShaderMaterial({
  transparent:true, blending:THREE.AdditiveBlending, depthWrite:false,
  uniforms:{ uTime:{value:0}, uCol:{value:new THREE.Color(hex)}, uAct:{value:0} },
  vertexShader:`varying vec3 vN; varying vec3 vP;
    void main(){ vN=normalize(normalMatrix*normal);
      vec4 mv=modelViewMatrix*vec4(position,1.0); vP=mv.xyz;
      gl_Position=projectionMatrix*mv; }`,
  fragmentShader:`uniform float uTime; uniform vec3 uCol; uniform float uAct;
    varying vec3 vN; varying vec3 vP;
    void main(){ vec3 V=normalize(-vP);
      float fres=pow(1.0-max(dot(vN,V),0.0),2.3);
      float band=0.5+0.5*sin(vP.y*9.0-uTime*2.8);
      gl_FragColor=vec4(uCol*(0.85+uAct*1.5), fres*(0.55+uAct*.8)+band*.11*(0.3+uAct)); }`
});
const sats = [];
P.forEach((p, i) => {
  const g = new THREE.Group(); g.position.copy(p);
  const c = new THREE.Mesh(new THREE.OctahedronGeometry(.42, 1), shellMat(COL[i]));
  g.add(c);
  const rings = [];
  [.68, .82, .96].forEach((r, k) => {
    const ring = new THREE.Mesh(new THREE.TorusGeometry(r, .012, 6, 80),
      new THREE.MeshBasicMaterial({ color:COL[i], transparent:true, opacity:.22,
        blending:THREE.AdditiveBlending, depthWrite:false }));
    ring.rotation.set(k*1.1, k*.7, k*.4);
    g.add(ring); rings.push(ring);
  });
  scene.add(g);
  sats.push({ group:g, core:c, rings });
});

/* ---------- spokes: core -> each agent, with flow pulses ---------- */
const flowMat = hex => new THREE.ShaderMaterial({
  transparent:true, blending:THREE.AdditiveBlending, depthWrite:false, side:THREE.DoubleSide,
  uniforms:{ uTime:{value:0}, uOn:{value:0}, uCol:{value:new THREE.Color(hex)} },
  vertexShader:`varying vec2 vUv; void main(){ vUv=uv;
    gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }`,
  fragmentShader:`uniform float uTime; uniform float uOn; uniform vec3 uCol; varying vec2 vUv;
    void main(){ float a=.04;
      for(int k=0;k<3;k++){
        float head=fract(vUv.x-uTime*.55+float(k)*.33);
        a+=(smoothstep(.95,1.,head)+smoothstep(.06,0.,head))*uOn*.5;
      }
      gl_FragColor=vec4(uCol*(1.+a*1.8), a); }`
});
const spokes = [], spokeCurves = [];
P.forEach((p, i) => {
  const mid = p.clone().multiplyScalar(.5); mid.y += 1.1;
  const curve = new THREE.CatmullRomCurve3([new THREE.Vector3(0,0,0), mid, p]);
  const m = flowMat(COL[i]);
  scene.add(new THREE.Mesh(new THREE.TubeGeometry(curve, 40, .035, 8, false), m));
  spokes.push(m); spokeCurves.push(curve);
});

/* ---------- data packets travelling core -> active agent ---------- */
const packets = [];
const packetGeo = new THREE.SphereGeometry(.09, 10, 10);
function spawnPacket(i){
  const mesh = new THREE.Mesh(packetGeo,
    new THREE.MeshBasicMaterial({ color:COL[i], transparent:true, opacity:.75,
      blending:THREE.AdditiveBlending, depthWrite:false }));
  scene.add(mesh);
  packets.push({ mesh, t:0, curve:spokeCurves[i] });
}

/* ---------- urgent shards: one red tetra per urgent finding (cap 14) ---------- */
const SHARD_CAP = 14;
const shards = [];
for (let i = 0; i < SHARD_CAP; i++){
  const s = new THREE.Mesh(new THREE.TetrahedronGeometry(.14),
    new THREE.MeshBasicMaterial({ color:0xff4d5e, transparent:true, opacity:0,
      blending:THREE.AdditiveBlending, depthWrite:false }));
  s.userData = { a:(i/SHARD_CAP)*Math.PI*2, r:2.55+((i%3)*.22), s:.6+Math.random()*.8 };
  scene.add(s); shards.push(s);
}

/* ---------- ambient dust ---------- */
const N = 220, dp = new Float32Array(N*3), ds = new Float32Array(N);
for (let i = 0; i < N; i++){
  dp[i*3]=(Math.random()-.5)*22; dp[i*3+1]=(Math.random()-.5)*9; dp[i*3+2]=(Math.random()-.5)*16;
  ds[i]=Math.random()*10;
}
const dg = new THREE.BufferGeometry();
dg.setAttribute('position', new THREE.BufferAttribute(dp,3));
dg.setAttribute('aSeed', new THREE.BufferAttribute(ds,1));
const dustMat = new THREE.ShaderMaterial({
  transparent:true, blending:THREE.AdditiveBlending, depthWrite:false,
  uniforms:{ uTime:{value:0} },
  vertexShader: NOISE + `attribute float aSeed; varying float vA; uniform float uTime;
    void main(){ vec3 p=position;
      p.x+=snoise(vec3(p.y*.2,p.z*.2,uTime*.1+aSeed))*.6;
      p.y+=snoise(vec3(p.z*.2,p.x*.2,uTime*.08+aSeed))*.5;
      vA=.12+.16*sin(uTime*1.2+aSeed*3.);
      vec4 mv=modelViewMatrix*vec4(p,1.0);
      gl_PointSize=2.4*(12./-mv.z); gl_Position=projectionMatrix*mv; }`,
  fragmentShader:`varying float vA; void main(){
    vec2 c=gl_PointCoord-.5; float d=length(c); if(d>.5) discard;
    gl_FragColor=vec4(.62,.42,.95,vA*smoothstep(.5,0.,d)); }`
});
scene.add(new THREE.Points(dg, dustMat));

/* ---------- projected labels ---------- */
const ov = $('p3dOv');
const labels = ov ? AGENTS.map((nm, i) => {
  const d = document.createElement('div'); d.className='lbl';
  d.innerHTML = `<div class="nm">${nm}</div><div class="st">جاهز</div>`;
  d.querySelector('.nm').style.setProperty('color', CSS[i]); // CSSOM: CSP-safe
  ov.appendChild(d); return d;
}) : [];
function updateLabels(){
  if (!ov) return;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  sats.forEach((s, i) => {
    const v = s.group.getWorldPosition(new THREE.Vector3()).project(camera);
    const el = labels[i];
    el.style.right = (w-(v.x*.5+.5)*w)+'px';
    el.style.top = ((-v.y*.5+.5)*h-56)+'px';
    el.style.opacity = v.z > 1 ? 0 : 1;
    const on = i === state.active, dn = i < state.doneUpTo;
    el.classList.toggle('on', on); el.classList.toggle('done', dn && !on);
    el.querySelector('.st').textContent = on ? 'قيد التنفيذ' : (dn ? 'مكتمل' : 'جاهز');
  });
}

/* ---------- optional HUD refs (host page may lack any of these) ---------- */
const m0=$('m0'), m1=$('m1'), m2=$('m2'), m3=$('m3'), f0=$('f0');
const card=$('card'), cardName=$('cardName'), cardDesc=$('cardDesc'),
      cardState=$('cardState'), cardX=$('cardX');
const lgEl = $('lg');
const setLog = t => { if (lgEl) lgEl.innerHTML = t; };

/* ---------- picking: click an agent to focus ---------- */
const ray = new THREE.Raycaster(), ndc = new THREE.Vector2();
canvas.addEventListener('click', e => {
  const r = canvas.getBoundingClientRect();
  ndc.set(((e.clientX-r.left)/r.width)*2-1, -((e.clientY-r.top)/r.height)*2+1);
  ray.setFromCamera(ndc, camera);
  const hit = ray.intersectObjects(sats.map(s=>s.core), false)[0];
  if (hit){
    state.selected = sats.findIndex(s => s.core === hit.object);
    if (card){
      cardName.textContent = AGENTS[state.selected];
      cardName.style.setProperty('color', CSS[state.selected]);
      cardDesc.textContent = DESC[state.selected];
      card.hidden = false;
    }
  } else {
    state.selected = -1; if (card) card.hidden = true;
  }
});
if (cardX) cardX.addEventListener('click', () => {
  state.selected = -1; card.hidden = true;
});

/* ---------- REAL app state (same-origin on purpose: no CORS headers exist) ---------- */
const API = '';
let csrf = null;
const actQueue = [];               // agent hand-offs waiting to be shown
let logCursor = null;              // how far into the real log we've read
let lastQueued = -1;               // tail of the queue (dedupe consecutive tags)
let lastSwitch = 0;                // when the displayed agent last changed
let scanRunning = false;
async function boot(){
  const c = $('conn');
  try{
    const r = await fetch(API+'/api/config'); if(!r.ok) throw 0;
    csrf = (await r.json()).csrfToken; state.live = true;
    if (c){ c.textContent='متصل بالتطبيق — بيانات حقيقية'; c.className='conn live'; }
  }catch{
    state.live = false;
    if (c){ c.textContent='التطبيق غير مفتوح — وضع عرض توضيحي'; c.className='conn off'; }
  }
}
async function pollReal(){
  if (!state.live || state.demo) return;
  try{
    const [s, d] = await Promise.all([
      fetch(API+'/api/status').then(r=>r.json()),
      fetch(API+'/api/decision').then(r=>r.json()),
    ]);
    const log = s.log || [];
    let act=-1, done=0;
    for (const line of log)
      KEYS.forEach((k,i)=>{ if(line.includes(`(${k})`)){ act=i; done=Math.max(done,i); } });
    // Don't set state.active from poll snapshots: with the NVD cache warm a
    // full scan finishes in ~3s, faster than one 800ms poll tick — snapshots
    // see only the final log line and the whole animation is skipped. Walk
    // the log itself with a cursor instead: every NEW line's agent tag is a
    // hand-off, queued in order; the render loop drains the queue with a
    // minimum on-screen dwell per agent, so even an instant scan plays out.
    scanRunning = !!s.running;
    if (logCursor === null) logCursor = log.length;   // don't replay history on page load
    if (log.length < logCursor) logCursor = 0;        // a new run reset the log
    for (; logCursor < log.length; logCursor++){
      const line = log[logCursor];
      for (let i = 0; i < KEYS.length; i++){
        if (line.includes(`(${KEYS[i]})`)){
          if (i !== lastQueued && actQueue.length < 16){ actQueue.push(i); lastQueued = i; }
          break;
        }
      }
    }
    state.doneUpTo = s.running ? done : (s.done ? AGENTS.length : 0);
    state.health = (d.health_score===undefined ? null : d.health_score);
    state.urgent = (d.urgent||[]).length;
    state.total  = (d.items||[]).length;
    const last = log[log.length-1] || '';
    setLog(s.running
      ? `▶ <span>${AGENTS[Math.max(act,0)]}</span> — ${last.replace(/^\[INFO\]\s*/,'').slice(0,110)}`
      : (s.done ? `✔ <span>اكتمل الفحص</span> — ${state.total} نتيجة · ${state.urgent} عاجلة` : '—'));
  }catch{ /* app closed mid-session */ }
}
setInterval(pollReal, 800); boot();

const runBtn3d = $('run');
if (runBtn3d) runBtn3d.addEventListener('click', async () => {
  if (!state.live){ setLog('⚠ افتح Securo أولاً لتشغيل فحص حقيقي'); return; }
  state.demo = false;
  try{
    await fetch(API+'/api/run', { method:'POST',
      headers:{ 'Content-Type':'application/json', 'X-CSRF-Token':csrf||'' } });
    setLog('▶ <span>بدأ الفحص الحقيقي</span> …');
  }catch{ setLog('⚠ تعذّر بدء الفحص'); }
});
const demoBtn = $('demo');
if (demoBtn) demoBtn.addEventListener('click', async () => {
  state.demo = true;
  state.health = 62; state.urgent = 5; state.total = 128;
  for (let i = 0; i < AGENTS.length; i++){
    state.active = i; state.doneUpTo = i;
    setLog(`▶ <span>${AGENTS[i]}</span> — عرض توضيحي`);
    await new Promise(r=>setTimeout(r,1800));
  }
  state.active = -1; state.doneUpTo = AGENTS.length;
  setLog('✔ <span>اكتمل العرض التوضيحي</span>');
  state.demo = false;
});

/* ---------- camera ---------- */
const mouse = { x:0, y:0 };
canvas.addEventListener('mousemove', e => {
  const r = canvas.getBoundingClientRect();
  mouse.x = ((e.clientX-r.left)/r.width-.5)*2;
  mouse.y = ((e.clientY-r.top)/r.height-.5)*2;
});
const camPos = new THREE.Vector3(0, 3.4, 11.5), camTgt = new THREE.Vector3(0, 0, 0);
function updateCamera(t){
  let want, look;
  if (state.selected >= 0){
    const p = sats[state.selected].group.position;
    want = p.clone().multiplyScalar(1.9).add(new THREE.Vector3(0, 1.6, 0));
    look = p;
  } else {
    const az = t*.07 + mouse.x*.55;
    want = new THREE.Vector3(Math.sin(az)*11.5, 3.4 - mouse.y*1.6, Math.cos(az)*11.5);
    look = new THREE.Vector3(0, .1, 0);
  }
  camPos.lerp(want, .04); camTgt.lerp(look, .06);
  camera.position.copy(camPos); camera.lookAt(camTgt);
}

/* ---------- main loop ---------- */
let t = 0, packetTimer = 0;
const MIN_DWELL_MS = 2500; // each agent stays lit at least this long
const healthCol = h => h===null ? 0x7c3aed : (h>=75 ? 0x3ddc84 : h>=45 ? 0xf5a524 : 0xff4d5e);

(function loop(){
  requestAnimationFrame(loop);
  if (document.hidden) return; // don't burn GPU for a tab nobody sees
  t += .016;

  // drain the hand-off queue with a minimum dwell so a cache-fast scan
  // still plays out visibly, one agent at a time
  if (!state.demo){
    const now = performance.now();
    if (actQueue.length && now - lastSwitch >= MIN_DWELL_MS){
      state.active = actQueue.shift(); lastSwitch = now;
    } else if (!scanRunning && !actQueue.length && state.active !== -1
               && now - lastSwitch >= MIN_DWELL_MS){
      state.active = -1; // scan over AND its animation fully played out
    }
  }
  updateCamera(t);

  coreMat.uniforms.uTime.value = t;
  coreMat.uniforms.uCol.value.lerp(new THREE.Color(healthCol(state.health)), .04);
  const beat = state.urgent>0 ? (.5+.5*Math.sin(t*5.5))*.7 : .15;
  coreMat.uniforms.uBeat.value += (beat - coreMat.uniforms.uBeat.value)*.08;
  core.rotation.y += .004;
  heart.material.color.lerp(new THREE.Color(healthCol(state.health)), .04);
  heart.scale.setScalar(1 + Math.sin(t*3)*.05 + (state.urgent>0 ? Math.sin(t*5.5)*.06 : 0));
  coreRings.forEach((r,k)=>{ r.rotation.z += (k? -.004 : .006);
    r.material.color.lerp(new THREE.Color(healthCol(state.health)), .04); });

  sats.forEach((s,i)=>{
    const on = i===state.active ? 1 : 0;
    const u = s.core.material.uniforms;
    u.uTime.value = t; u.uAct.value += (on-u.uAct.value)*.09;
    const a = u.uAct.value;
    s.core.rotation.y += .006+on*.04; s.core.rotation.x += .003;
    s.core.scale.setScalar(1+a*.5+(on?Math.sin(t*7)*.05:0));
    s.rings.forEach((r,k)=>{
      r.rotation.x += (.004+(k+1)*.003)*(1+a*3);
      r.rotation.y += (.003+(k+1)*.002)*(1+a*3);
      r.material.opacity = .18+a*.45;
    });
    s.group.position.y = P[i].y + Math.sin(t*.9+i*2)*0.12;
  });

  spokes.forEach((m,i)=>{
    m.uniforms.uTime.value = t;
    const on = i===state.active ? 1 : 0;
    m.uniforms.uOn.value += (on-m.uniforms.uOn.value)*.1;
  });

  if (state.active >= 0){
    packetTimer -= .016;
    if (packetTimer <= 0){ spawnPacket(state.active); packetTimer = .38; }
  }
  for (let i = packets.length-1; i >= 0; i--){
    const p = packets[i]; p.t += .022;
    if (p.t >= 1){ scene.remove(p.mesh); p.mesh.material.dispose(); packets.splice(i,1); continue; }
    p.curve.getPoint(p.t, p.mesh.position);
    p.mesh.material.opacity = .75*(1-Math.abs(p.t-.5)*.6);
  }

  const liveShards = Math.min(state.urgent, SHARD_CAP);
  shards.forEach((s,i)=>{
    const u = s.userData; u.a += .004*u.s;
    s.position.set(Math.cos(u.a)*u.r, Math.sin(t*u.s+i)*.5, Math.sin(u.a)*u.r);
    s.rotation.x += .02; s.rotation.y += .017;
    const want = i < liveShards ? .65 : 0;
    s.material.opacity += (want - s.material.opacity)*.06;
  });

  starMat.uniforms.uTime.value = t;
  dustMat.uniforms.uTime.value = t;
  // calmer glow ceiling: idle .5, scanning .72, urgent adds a touch
  bloom.strength += (((state.active>=0?0.72:0.5)+(state.urgent>0?0.12:0)) - bloom.strength)*.05;

  updateLabels();
  if (m0){
    m0.textContent = state.health===null ? '—' : state.health;
    m0.style.setProperty('color', state.health===null ? '' :
      (state.health>=75 ? CSS[3] : state.health>=45 ? CSS[2] : '#ff4d5e'));
  }
  if (f0){
    f0.style.setProperty('width', (state.health||0)+'%');
    f0.style.setProperty('background', state.health===null ? '#7c3aed' :
      (state.health>=75 ? CSS[3] : state.health>=45 ? CSS[2] : '#ff4d5e'));
  }
  if (m1){
    m1.textContent = state.urgent || '0';
    m1.style.setProperty('color', state.urgent>0 ? '#ff4d5e' : '');
  }
  if (m2) m2.textContent = state.total || '—';
  if (m3) m3.textContent = state.active>=0 ? AGENTS[state.active] : '—';
  if (card && cardState && state.selected >= 0)
    cardState.textContent = state.selected===state.active ? 'يعمل الآن'
      : (state.selected < state.doneUpTo ? 'مكتمل' : 'بانتظار');

  composer.render();
})();

}
