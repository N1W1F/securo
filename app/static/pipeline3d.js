/* Securo pipeline3d — the live orbital agent scene in the main dashboard.
   Every HUD element is looked up by id and skipped if absent, so the scene
   degrades cleanly if the host page omits any of them.
   Central reactor = live health score; agent satellites orbit it; the active
   agent is derived from the REAL execution log; urgent findings appear as
   red shards. Click an agent to fly the camera to it. */
import * as THREE from '/vendor/three/three.module.js';
import { EffectComposer } from '/vendor/three/addons/postprocessing/EffectComposer.js';
import { RenderPass }     from '/vendor/three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass }from '/vendor/three/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass }     from '/vendor/three/addons/postprocessing/OutputPass.js';

// All EIGHT agents, in pipeline order. The scene used to render only the four
// that run inside the scan subprocess and therefore appear in the scan log;
// the other four run in the server process, so half the architecture was
// invisible and the app looked like a 4-agent system.
//
// `log` = the tag this agent writes into the scan log (subprocess agents).
// `api` = the name the server reports on /api/agents (in-process agents).
// An agent has exactly one of the two — that is precisely the split.
const AGENTS_DEF = [
  { log:"Orchestrator",    name:"stageOrchestrator",   desc:"agentDescOrchestrator",   col:0xa855f7 },
  { log:"Asset Auditor",   name:"stageAssetAuditor",   desc:"agentDescAuditor",        col:0xf5a524 },
  { api:"Package Manager", name:"stagePackageManager", desc:"agentDescPackageManager", col:0xf59e0b },
  { log:"Threat Hunter",   name:"stageThreatHunter",   desc:"agentDescHunter",         col:0x22d3ee },
  { api:"KEV Checker",     name:"stageKevChecker",     desc:"agentDescKev",            col:0x38bdf8 },
  { api:"Decision",        name:"stageDecision",       desc:"agentDescDecision",       col:0x818cf8 },
  { log:"Remediation",     name:"stageRemediation",    desc:"agentDescRemediation",    col:0x3ddc84 },
  { api:"Analyst",         name:"stageAnalyst",        desc:"agentDescAnalyst",        col:0xc084fc },
];
const KEYS      = AGENTS_DEF.map(a => a.log || a.api);   // stable identity per slot
const LOG_TAGS  = AGENTS_DEF.map(a => a.log || null);
const API_NAMES = AGENTS_DEF.map(a => a.api || null);
// Names/descriptions are read from the shared i18n table on every use, not
// snapshotted into a const, so the scene follows the language switch instead
// of staying in whatever language the page loaded in. i18n.js is a classic
// script loaded before this module, so `t` exists.
const tr        = k => (typeof t === "function" ? t(k) : k);
const AGENT_N   = AGENTS_DEF.length;
const agentName = i => tr(AGENTS_DEF[i].name);
const agentDesc = i => tr(AGENTS_DEF[i].desc);
const COL = AGENTS_DEF.map(a => a.col);
const CSS = COL.map(c => "#" + c.toString(16).padStart(6, "0"));

const $ = id => document.getElementById(id);
const canvas = $('p3d');
if (canvas) init();

function init(){

const state = { active:-1, doneUpTo:0, health:null, urgent:0, total:0,
                live:false, selected:-1 };

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
// Threshold raised and strength cut: the sculpted silhouettes are the
// point now, and the old settings melted their edges back into orbs.
const bloom = new UnrealBloomPass(new THREE.Vector2(1,1), 0.34, 0.42, 0.42);
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

/* ---------- the centre: the Orchestrator itself ----------
   It was an abstract "reactor" with the Orchestrator demoted to one more
   satellite. That contradicted the architecture: the Orchestrator is what
   calls every other agent, so it belongs at the hub with the spokes leaving
   it. Its own sculpted form is used (shape field 0), and its colour carries
   the health score — the coordinator showing the state of what it runs. */
const CORE_INDEX = 0;
let coreMat;      // assigned once the shared shell material is defined
let core, heart, coreRings = [];

/* ---------- agent satellites ----------
   Each agent gets a geometry that states what it DOES, so the scene can be
   read without the labels, plus its own orbit. Eight identical octahedrons
   on one fixed ring said nothing and read as decoration.

   Orbits differ in radius, speed, inclination and phase so the ring never
   collapses into a line and the system reads as alive rather than posed.
   Inner orbits = earlier pipeline stages. */
// Seven orbits — the Orchestrator is the hub and does not orbit anything.
// Index 0 is a placeholder so every array here stays aligned with AGENTS_DEF.
const ORBITS = [
  null,                                              // Orchestrator (centre)
  { r:3.55, speed:0.115, tilt:0.46, phase:0.80 },   // Asset Auditor
  { r:4.30, speed:0.100, tilt:-0.40, phase:1.70 },  // Package Manager
  { r:4.95, speed:0.082, tilt:0.62, phase:2.55 },   // Threat Hunter
  { r:5.55, speed:0.075, tilt:-0.58, phase:3.45 },  // KEV Checker
  { r:6.05, speed:0.064, tilt:0.34, phase:4.35 },   // Decision
  { r:6.55, speed:0.058, tilt:-0.66, phase:5.20 },  // Remediation
  { r:7.00, speed:0.048, tilt:0.52, phase:6.05 },   // Analyst
];

// Every agent is the SAME icosphere, sculpted into a different form by a
// displacement field chosen per agent in the vertex shader. Nothing here is
// a stock Three.js primitive — reaching for TorusKnot/Box/Cone/Tetrahedron is
// exactly the built-in-dropdown look, and it reads as a demo rather than a
// designed system.
//
// Each field is a signature, not decoration:
//   0 Orchestrator  smooth 3-lobe harmonic breathing — many strands, one will
//   1 Asset Auditor terraced shelves — a catalogue, quantised into records
//   2 Package Mgr   sphere morphed toward a superquadric block — a crate
//   3 Threat Hunter drawn to a point, with a ripple sweeping the surface
//   4 KEV Checker   hard radial spines — confirmed, weaponised exploitation
//   5 Decision      split into two offset hemispheres — weighing both sides
//   6 Remediation   pulled outward into a closed ring — finding to fix
//   7 Analyst       dense folded convolutions — a model, many parameters
const AGENT_GEO = new THREE.IcosahedronGeometry(0.62, 4);

const SHAPE_GLSL = `
// --- displacement fields ---------------------------------------------------
// Each returns a radial offset for a unit-sphere direction n.
float fOrchestrator(vec3 n, float tm){
  // three lobes rotating slowly about the pole
  float a = atan(n.z, n.x);
  return 0.52 * sin(3.0 * a + tm * 0.6) * (1.0 - n.y * n.y)
       + 0.10 * sin(tm * 1.3);
}
float fAuditor(vec3 n, float tm){
  // terraces: quantise latitude into shelves, so the silhouette steps
  float lat = n.y;
  float steps = 5.0;
  return 0.90 * (floor(lat * steps) / steps - lat) + 0.10;
}
float fPackage(vec3 n, float tm){
  // push toward a rounded block: the superquadric distance for p=6
  vec3 a = abs(n);
  float box = pow(pow(a.x, 6.0) + pow(a.y, 6.0) + pow(a.z, 6.0), 1.0 / 6.0);
  return (1.0 / max(box, 0.15) - 1.0) * 0.85;
}
float fHunter(vec3 n, float tm){
  // taper to a probe tip along +Y, with a scan ripple travelling down it
  float taper = 0.85 * pow(n.y * 0.5 + 0.5, 2.0) - 0.30 * (1.0 - abs(n.y));
  float ripple = 0.09 * sin(n.y * 14.0 - tm * 3.4);
  return taper + ripple;
}
float fKev(vec3 n, float tm){
  // hard spines: keep only the sharp peaks of a cheap 3-axis interference
  float k = sin(n.x * 7.0) * sin(n.y * 7.0) * sin(n.z * 7.0);
  return 1.05 * smoothstep(0.30, 1.0, abs(k)) - 0.10;
}
float fDecision(vec3 n, float tm){
  // two hemispheres pulled apart, with a clean equatorial gap
  float side = sign(n.y);
  float gap  = smoothstep(0.0, 0.22, abs(n.y));
  return side * 0.40 * gap + 0.22 * gap - 0.26;
}
float fRemediation(vec3 n, float tm){
  // collapse the poles and push out the equator: a closed loop
  float eq = 1.0 - abs(n.y);
  return 0.85 * pow(eq, 3.0) - 0.55 * abs(n.y);
}
float fAnalyst(vec3 n, float tm){
  // folded convolutions at two frequencies, slowly reorganising
  float f = sin(n.x * 9.0 + tm * .5) * sin(n.y * 9.0 - tm * .4) * sin(n.z * 9.0)
          + 0.5 * sin(n.x * 17.0) * sin(n.z * 17.0);
  return 0.30 * f;
}

float shapeField(int id, vec3 n, float tm){
  if (id == 0) return fOrchestrator(n, tm);
  if (id == 1) return fAuditor(n, tm);
  if (id == 2) return fPackage(n, tm);
  if (id == 3) return fHunter(n, tm);
  if (id == 4) return fKev(n, tm);
  if (id == 5) return fDecision(n, tm);
  if (id == 6) return fRemediation(n, tm);
  return fAnalyst(n, tm);
}
`;

const shellMat = (hex, shapeId) => new THREE.ShaderMaterial({
  transparent:true, blending:THREE.AdditiveBlending, depthWrite:false,
  side:THREE.DoubleSide,
  uniforms:{ uTime:{value:0}, uCol:{value:new THREE.Color(hex)}, uAct:{value:0},
             uShape:{value:shapeId} },
  vertexShader: SHAPE_GLSL + `
    uniform float uTime; uniform float uAct; uniform int uShape;
    varying vec3 vN; varying vec3 vP; varying float vD;

    vec3 sculpt(vec3 n, float tm){
      return n * (1.0 + shapeField(uShape, n, tm));
    }
    void main(){
      vec3 n = normalize(position);
      float tm = uTime;
      vec3 p = sculpt(n, tm) * 0.62;
      vD = shapeField(uShape, n, tm);

      // Rebuild the normal from the sculpted surface. Using the sphere's
      // original normal left every agent lit identically, which threw away
      // the silhouette the displacement had just created.
      vec3 t1 = normalize(abs(n.y) < 0.99 ? cross(n, vec3(0.0,1.0,0.0)) : vec3(1.0,0.0,0.0));
      vec3 t2 = cross(n, t1);
      float e = 0.04;
      vec3 pa = sculpt(normalize(n + t1 * e), tm) * 0.62;
      vec3 pb = sculpt(normalize(n + t2 * e), tm) * 0.62;
      vec3 nrm = normalize(cross(pa - p, pb - p));
      if (dot(nrm, n) < 0.0) nrm = -nrm;

      vN = normalize(normalMatrix * nrm);
      vec4 mv = modelViewMatrix * vec4(p, 1.0); vP = mv.xyz;
      gl_Position = projectionMatrix * mv;
    }`,
  fragmentShader:`uniform float uTime; uniform vec3 uCol; uniform float uAct;
    varying vec3 vN; varying vec3 vP; varying float vD;
    void main(){
      vec3 V = normalize(-vP);
      float fres = pow(1.0 - max(dot(vN, V), 0.0), 3.0);
      // ridges catch the light: the parts pushed furthest out read brightest,
      // so each field's structure is legible instead of a uniform glow
      float ridge = smoothstep(-0.05, 0.45, vD);
      vec3 col = uCol * (0.55 + uAct * 1.3 + ridge * 1.5);
      gl_FragColor = vec4(col, fres * (0.32 + uAct * 0.5) + ridge * 0.52 * (0.45 + uAct));
    }`
});

// Live positions — recomputed every frame from the orbits.
const P = ORBITS.map(() => new THREE.Vector3());
function orbitPosition(i, time, out){
  const o = ORBITS[i];
  if (!o) return out.set(0, 0, 0);      // the hub sits at the origin
  const a = o.phase + time * o.speed;
  return out.set(Math.cos(a) * o.r, Math.sin(a) * o.r * o.tilt, Math.sin(a) * o.r);
}
ORBITS.forEach((_, i) => orbitPosition(i, 0, P[i]));

// The hub is bigger than the agents it drives, and its own material is kept
// on `coreMat` so the render loop can drive its colour from the health score.
const HUB_GEO = new THREE.IcosahedronGeometry(0.62, 5);
coreMat = shellMat(COL[CORE_INDEX], CORE_INDEX);

const sats = [];
P.forEach((pos, i) => {
  const g = new THREE.Group(); g.position.copy(pos);
  const isHub = i === CORE_INDEX;
  const c = new THREE.Mesh(isHub ? HUB_GEO : AGENT_GEO,
                           isHub ? coreMat : shellMat(COL[i], i));
  if (isHub) { c.scale.setScalar(1.45); core = c; }
  g.add(c);
  // One gyro ring instead of three: with eight distinct bodies the triple
  // rings turned the scene into overlapping wire soup.
  const rings = [];
  if (isHub) {
    // Two counter-rotating equator rings mark the hub as the thing everything
    // else revolves around.
    [1.30, 1.58].forEach((r, k) => {
      const ring = new THREE.Mesh(new THREE.TorusGeometry(r, .014, 8, 128),
        new THREE.MeshBasicMaterial({ color:COL[i], transparent:true, opacity:.26,
          blending:THREE.AdditiveBlending, depthWrite:false }));
      ring.rotation.x = Math.PI/2 + (k ? .28 : -.18);
      g.add(ring); rings.push(ring); coreRings.push(ring);
    });
    heart = new THREE.Mesh(new THREE.SphereGeometry(.24, 24, 24),
      new THREE.MeshBasicMaterial({ color:0xffffff, transparent:true, opacity:.5,
        blending:THREE.AdditiveBlending, depthWrite:false }));
    g.add(heart);
  } else {
    const ring = new THREE.Mesh(new THREE.TorusGeometry(1.02, .009, 6, 72),
      new THREE.MeshBasicMaterial({ color:COL[i], transparent:true, opacity:.18,
        blending:THREE.AdditiveBlending, depthWrite:false }));
    ring.rotation.set(i * 0.7, i * 0.4, 0);
    g.add(ring); rings.push(ring);
  }
  scene.add(g);
  sats.push({ group:g, core:c, rings });
});

/* ---------- spokes: core -> each agent ----------
   Dynamic lines, not tube meshes. The agents now move, and rebuilding eight
   40-segment TubeGeometries every frame to follow them would cost more than
   the rest of the scene combined. Two vertices per spoke, rewritten in place. */
const spokes = [];
P.forEach((pos, i) => {
  if (i === CORE_INDEX) { spokes.push(null); return; }   // the hub is the origin
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(6), 3));
  const mat = new THREE.LineBasicMaterial({ color:COL[i], transparent:true, opacity:.12,
    blending:THREE.AdditiveBlending, depthWrite:false });
  const line = new THREE.Line(geo, mat);
  scene.add(line);
  spokes.push({ geo, mat });
});

function updateSpokes(){
  for (let i = 0; i < spokes.length; i++){
    if (!spokes[i]) continue;
    const a = spokes[i].geo.attributes.position;
    a.setXYZ(0, 0, 0, 0);
    a.setXYZ(1, P[i].x, P[i].y, P[i].z);
    a.needsUpdate = true;
  }
}

/* ---------- data packets travelling core -> active agent ---------- */
const packets = [];
const packetGeo = new THREE.SphereGeometry(.09, 10, 10);
function spawnPacket(i){
  const mesh = new THREE.Mesh(packetGeo,
    new THREE.MeshBasicMaterial({ color:COL[i], transparent:true, opacity:.75,
      blending:THREE.AdditiveBlending, depthWrite:false }));
  scene.add(mesh);
  // Target index, not a frozen curve: the destination is moving, so a packet
  // must re-aim at where its agent is NOW or it flies off to a stale point.
  packets.push({ mesh, t:0, target:i });
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
const labels = ov ? KEYS.map((_, i) => {
  const d = document.createElement('div'); d.className='lbl';
  d.innerHTML = `<div class="nm"></div><div class="st"></div>`;
  const nm = d.querySelector('.nm');
  nm.textContent = agentName(i);
  nm.style.setProperty('color', CSS[i]); // CSSOM: CSP-safe
  ov.appendChild(d); return d;
}) : [];
function updateLabels(){
  if (!ov) return;
  const w = canvas.clientWidth, h = canvas.clientHeight;

  // Pass 1: project every agent to screen space and record its depth.
  const placed = [];
  sats.forEach((s, i) => {
    const world = s.group.getWorldPosition(new THREE.Vector3());
    const dist = camera.position.distanceTo(world);
    const v = world.clone().project(camera);
    placed.push({
      i,
      behind: v.z > 1,
      x: (v.x * .5 + .5) * w,          // from the LEFT edge
      y: (-v.y * .5 + .5) * h - 52,
      dist,
    });
  });

  // Pass 2: de-collide vertically. Eight bodies on eight orbits regularly
  // line up on screen; a fixed per-index offset still stacked neighbours into
  // an unreadable pile. Nearest-to-camera keeps its spot and anything behind
  // it that would overlap gets pushed down, so the front label — the one the
  // user is most likely reading — never moves.
  const LBL_W = 108, LBL_H = 30;
  placed.sort((a, b) => a.dist - b.dist);
  const taken = [];
  for (const p of placed) {
    if (p.behind) continue;
    let guard = 0;
    while (guard++ < 12 && taken.some(q =>
             Math.abs(q.x - p.x) < LBL_W && Math.abs(q.y - p.y) < LBL_H)) {
      p.y += LBL_H;
    }
    taken.push(p);
  }

  // Pass 3: write to the DOM.
  for (const p of placed) {
    const el = labels[p.i];
    el.style.right = (w - p.x) + 'px';
    el.style.top = p.y + 'px';
    // Fade with depth so the far side of the ring recedes instead of
    // competing with the agents in front of it.
    //
    // Uses real camera distance, NOT the projected z: perspective NDC z is
    // nonlinear and pins almost everything to ~0.99, which faded all eight
    // labels to the same minimum instead of separating near from far.
    const depth = Math.min(1, Math.max(0, (p.dist - 7) / 14));
    el.style.opacity = p.behind ? '0' : (1 - depth * 0.62).toFixed(2);

    const on = p.i === state.active || apiActive[p.i], dn = p.i < state.doneUpTo;
    el.classList.toggle('on', on); el.classList.toggle('done', dn && !on);
    el.querySelector('.st').textContent =
      on ? tr('agentRunning') : (dn ? tr('stageDone') : tr('stageReady'));
  }
}

/* ---------- optional HUD refs (host page may lack any of these) ---------- */
const m0=$('m0'), m1=$('m1'), m2=$('m2'), m3=$('m3'), f0=$('f0');
const card=$('card'), cardName=$('cardName'), cardDesc=$('cardDesc'),
      cardState=$('cardState'), cardX=$('cardX');

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
      cardName.textContent = agentName(state.selected);
      cardName.style.setProperty('color', CSS[state.selected]);
      cardDesc.textContent = agentDesc(state.selected);
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
let apiActive = [];   // per-slot busy flags for the in-process agents
async function boot(){
  try{
    const r = await fetch(API+'/api/config'); if(!r.ok) throw 0;
    csrf = (await r.json()).csrfToken; state.live = true;
  }catch{
    state.live = false;   // scene keeps rendering, just with no live numbers
  }
}
async function pollReal(){
  if (!state.live) return;
  try{
    const [s, d] = await Promise.all([
      fetch(API+'/api/status').then(r=>r.json()),
      fetch(API+'/api/decision').then(r=>r.json()),
    ]);
    const log = s.log || [];
    let act=-1, done=0;
    for (const line of log)
      LOG_TAGS.forEach((k,i)=>{ if(k && line.includes(`(${k})`)){ act=i; done=Math.max(done,i); } });
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
      for (let i = 0; i < LOG_TAGS.length; i++){
        if (LOG_TAGS[i] && line.includes(`(${LOG_TAGS[i]})`)){
          if (i !== lastQueued && actQueue.length < 16){ actQueue.push(i); lastQueued = i; }
          break;
        }
      }
    }

    // In-process agents never reach the scan log, so ask the server directly.
    try{
      const a = await fetch(API+'/api/agents').then(r=>r.json());
      const busy = new Set(a.active || []);
      apiActive = API_NAMES.map(n => !!(n && busy.has(n)));
    }catch{ apiActive = API_NAMES.map(()=>false); }
    state.doneUpTo = s.running ? done : (s.done ? AGENT_N : 0);
    state.health = (d.health_score===undefined ? null : d.health_score);
    state.urgent = (d.urgent||[]).length;
    state.total  = (d.items||[]).length;
  }catch{ /* app closed mid-session */ }
}
setInterval(pollReal, 800); boot();

/* ---------- camera ---------- */
const mouse = { x:0, y:0 };
canvas.addEventListener('mousemove', e => {
  const r = canvas.getBoundingClientRect();
  mouse.x = ((e.clientX-r.left)/r.width-.5)*2;
  mouse.y = ((e.clientY-r.top)/r.height-.5)*2;
});
// Outermost orbit is 7.0, so the framing distance has to clear it plus
// room for the projected labels above each body.
const CAM_DIST = 14.2;
const camPos = new THREE.Vector3(0, 4.6, CAM_DIST), camTgt = new THREE.Vector3(0, 0, 0);
// Advanced only while the scene is busy, so the framing holds still when
// the user is reading rather than sliding out from under them.
let camAz = 0;
function updateCamera(t){
  camAz += .07 * .016 * mt;
  let want, look;
  if (state.selected >= 0){
    const p = sats[state.selected].group.position;
    // fixed offset outward from the body, not a scale of its orbit radius:
    // scaling put the camera 14 units away for the outer agents
    want = p.clone().normalize().multiplyScalar(p.length() + 3.4).add(new THREE.Vector3(0, 1.5, 0));
    look = p;
  } else {
    // Camera auto-orbit was the worst offender: the whole frame slid even
    // when nothing was happening. It now only drifts while busy; the mouse
    // still steers at any time.
    const az = camAz + mouse.x*.55;
    want = new THREE.Vector3(Math.sin(az)*CAM_DIST, 4.6 - mouse.y*2.0, Math.cos(az)*CAM_DIST);
    look = new THREE.Vector3(0, .1, 0);
  }
  camPos.lerp(want, .04); camTgt.lerp(look, .06);
  camera.position.copy(camPos); camera.lookAt(camTgt);
}

/* ---------- motion gate ----------
   This is a dashboard panel, not a screensaver. Eight bodies orbiting, each
   bobbing, each spinning, with the camera drifting on top, is a lot of motion
   competing with a security report the user is trying to read.

   So motion means "work is happening" instead of running forever: the scene
   settles to near-still when idle and comes alive while a scan runs. That is
   calmer AND more informative than constant ambient drift.

   `mt` is the eased gate; `tm` is a motion-scaled clock, so anything driven
   by it slows to a stop rather than snapping. */
// Zero, not 'slow'. Any residual orbital drift still pulls the eye away
// from the report; the scene should be genuinely still until there is
// something to report. Liveness at rest comes from the star twinkle and
// the urgent pulse, which do not move anything the user is reading.
const REST_MOTION = 0;
let mt = REST_MOTION, tm = 0, lastFrame = performance.now();
const reduceMotion = matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ---------- main loop ---------- */
let t = 0, packetTimer = 0;
const MIN_DWELL_MS = 2500; // each agent stays lit at least this long
const healthCol = h => h===null ? 0x7c3aed : (h>=75 ? 0x3ddc84 : h>=45 ? 0xf5a524 : 0xff4d5e);

(function loop(){
  requestAnimationFrame(loop);
  if (document.hidden) return; // don't burn GPU for a tab nobody sees
  t += .016;

  // Busy when a scan is running, an agent is dispatching, or an in-process
  // agent is working. Otherwise ease back to rest.
  const now = performance.now();
  // Clamped: a backgrounded tab can hand back a multi-second delta, which
  // would snap the gate open and jump every orbit forward at once.
  const dt = Math.min((now - lastFrame) / 1000, 0.05);
  lastFrame = now;

  const busy = scanRunning || state.active >= 0 || apiActive.some(Boolean);
  const wantMotion = reduceMotion ? 0 : (busy ? 1 : REST_MOTION);
  // Time-based ease (~1.2s to settle) instead of a per-frame constant, which
  // opened the gate at a different speed on every refresh rate.
  mt += (wantMotion - mt) * Math.min(1, dt * 2.6);
  tm += dt * mt;

  // drain the hand-off queue with a minimum dwell so a cache-fast scan
  // still plays out visibly, one agent at a time
  {
    const now = performance.now();
    if (actQueue.length && now - lastSwitch >= MIN_DWELL_MS){
      state.active = actQueue.shift(); lastSwitch = now;
    } else if (!scanRunning && !actQueue.length && state.active !== -1
               && now - lastSwitch >= MIN_DWELL_MS){
      state.active = -1; // scan over AND its animation fully played out
    }
  }
  updateCamera(t);

  // The hub's colour is the health score: the coordinator showing the state
  // of the system it coordinates. It shares the agents' shell material, so it
  // has no separate `uBeat` uniform — urgency rides on uAct instead, which the
  // satellite loop below already drives.
  const hubCol = new THREE.Color(healthCol(state.health));
  coreMat.uniforms.uCol.value.lerp(hubCol, .04);
  heart.material.color.lerp(hubCol, .04);
  // Breath is gated with everything else; the urgency pulse is not, because
  // it is a warning rather than ambience.
  heart.scale.setScalar(1 + Math.sin(tm*3)*.05*mt + (state.urgent>0 ? Math.sin(t*5.5)*.06 : 0));
  coreRings.forEach((r,k)=>{ r.rotation.z += (k? -.004 : .006) * mt;
    r.material.color.lerp(hubCol, .04); });

  sats.forEach((s,i)=>{
    let on = (i===state.active || apiActive[i]) ? 1 : 0;
    // The hub glows with urgency even when idle — it represents the whole
    // system's posture, not just whether it happens to be dispatching now.
    if (i === CORE_INDEX && state.urgent > 0) on = Math.max(on, .45 + .35*Math.sin(t*5.5));
    const u = s.core.material.uniforms;
    u.uTime.value = tm; u.uAct.value += (on-u.uAct.value)*.09;
    const a = u.uAct.value;

    if (i === CORE_INDEX){
      // The hub does not orbit — it is what the others orbit around.
      P[i].set(0, 0, 0);
    } else {
      // Advance the orbit. An active agent speeds up slightly — the motion
      // itself reports state, so the scene reads even at a glance.
      orbitPosition(i, tm * (1 + a * 0.8), P[i]);
      P[i].y += Math.sin(tm*.9 + i*2) * 0.12 * mt;    // gentle bob, so the ring never looks printed
    }
    s.group.position.copy(P[i]);

    // Each body tumbles on its own axis mix so identical-looking rotation
    // doesn't flatten the distinct shapes back into one silhouette.
    s.core.rotation.y += (.006 + i*.0009) * mt + on*.04;
    s.core.rotation.x += (.003 + i*.0005) * mt;
    s.core.scale.setScalar(1+a*.5+(on?Math.sin(t*7)*.05:0));
    s.rings.forEach((r)=>{
      r.rotation.x += .005*(1+a*3)*Math.max(mt, a);
      r.rotation.z += .004*(1+a*3)*Math.max(mt, a);
      r.material.opacity = .14+a*.5;
    });
  });

  updateSpokes();
  spokes.forEach((sp,i)=>{
    if (!sp) return;
    const on = (i===state.active || apiActive[i]) ? 1 : 0;
    sp.mat.opacity += ((on ? .55 : .10) - sp.mat.opacity)*.1;
  });

  if (state.active >= 0 && state.active !== CORE_INDEX){
    packetTimer -= .016;
    if (packetTimer <= 0){ spawnPacket(state.active); packetTimer = .38; }
  }
  for (let i = packets.length-1; i >= 0; i--){
    const p = packets[i]; p.t += .022;
    if (p.t >= 1){ scene.remove(p.mesh); p.mesh.material.dispose(); packets.splice(i,1); continue; }
    // Re-aim at the target's CURRENT position each frame — it is orbiting.
    const dst = P[p.target];
    p.mesh.position.set(dst.x*p.t, dst.y*p.t, dst.z*p.t);
    p.mesh.material.opacity = .75*(1-Math.abs(p.t-.5)*.6);
  }

  const liveShards = Math.min(state.urgent, SHARD_CAP);
  shards.forEach((s,i)=>{
    const u = s.userData; u.a += .004*u.s*mt;
    s.position.set(Math.cos(u.a)*u.r, Math.sin(t*u.s+i)*.5, Math.sin(u.a)*u.r);
    s.rotation.x += .02*mt; s.rotation.y += .017*mt;
    const want = i < liveShards ? .65 : 0;
    s.material.opacity += (want - s.material.opacity)*.06;
  });

  starMat.uniforms.uTime.value = t;    // twinkle is the one thing that never stops:
                                       // it signals 'alive' without moving any element
  dustMat.uniforms.uTime.value = tm;
  // calmer glow ceiling: idle .5, scanning .72, urgent adds a touch
  bloom.strength += (((state.active>=0?0.50:0.34)+(state.urgent>0?0.10:0)) - bloom.strength)*.05;

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
  if (m3) m3.textContent = state.active>=0 ? agentName(state.active) : '—';
  if (card && cardState && state.selected >= 0)
    cardState.textContent = state.selected===state.active ? tr('agentRunning')
      : (state.selected < state.doneUpTo ? tr('stageDone') : tr('agentWaiting'));

  composer.render();
})();

}
