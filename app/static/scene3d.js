// 3D interactive layer (Three.js, vendored locally — see vendor/PROVENANCE.md).
// Two independent scenes:
//   1. An ambient full-viewport particle-network background. Node color and
//      density are driven by REAL decision-agent data (setThreatLevel), not
//      decoration for its own sake — more/redder particles = worse posture.
//   2. A small 3D "health orb" replacing the flat gauge ring, colored and
//      spun by the real health score.
// Both respect prefers-reduced-motion (freeze instead of animate) and pause
// entirely when the tab is hidden. If WebGL is unavailable for any reason,
// everything here no-ops silently and the existing flat CSS/SVG visuals
// (already fully functional on their own) are the fallback — nothing here
// is load-bearing for the app to work.

// Imports the SAME ESM build pipeline3d.js uses. This file used to be a
// classic script against the legacy UMD three.min.js, which meant the app
// shipped TWO complete copies of Three.js (654 KB UMD + 1295 KB ESM) and
// parsed both on every launch. One module, one copy, one parse.
import * as THREE from '/vendor/three/three.module.js';

(function () {
  "use strict";

  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let tabHidden = document.hidden;
  document.addEventListener("visibilitychange", () => { tabHidden = document.hidden; });

  function makeGlowTexture(hex) {
    // Procedural radial-gradient sprite — no external image asset needed,
    // keeps this fully offline with zero new files.
    const size = 128;
    const c = document.createElement("canvas");
    c.width = c.height = size;
    const ctx = c.getContext("2d");
    const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
    g.addColorStop(0, hex);
    g.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, size, size);
    return new THREE.CanvasTexture(c);
  }

  // ---------------------------------------------------------------------
  // Scene 1: calm deep-space starfield background (replaced the old red
  // particle network — that read as "alarm" everywhere, all the time)
  // ---------------------------------------------------------------------
  function initAmbient() {
    const canvas = document.getElementById("scene3dBg");
    if (!canvas) return null;
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    } catch {
      return null; // no WebGL context available — fine, CSS background stays visible
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(55, 1, 0.1, 100);
    camera.position.z = 18;

    // three star layers with slightly different tints; each layer's opacity
    // breathes on its own phase for a slow collective twinkle
    const starLayers = [];
    const LAYER_SPECS = [
      { count: 220, color: 0xffffff, size: 0.32, baseOp: 0.55 },
      { count: 140, color: 0xbfa8ff, size: 0.42, baseOp: 0.38 }, // faint violet
      { count: 110, color: 0x9fc8ff, size: 0.26, baseOp: 0.30 }, // ice blue
    ];
    const sprite = makeGlowTexture("rgba(255,255,255,0.95)");
    for (const spec of LAYER_SPECS) {
      const pos = new Float32Array(spec.count * 3);
      for (let i = 0; i < spec.count; i++) {
        pos[i * 3] = (Math.random() - 0.5) * 44;
        pos[i * 3 + 1] = (Math.random() - 0.5) * 26;
        pos[i * 3 + 2] = (Math.random() - 0.5) * 18 - 4;
      }
      const geo = new THREE.BufferGeometry();
      geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
      const material = new THREE.PointsMaterial({
        size: spec.size, map: sprite, transparent: true, depthWrite: false,
        blending: THREE.AdditiveBlending, color: spec.color, opacity: spec.baseOp,
      });
      const points = new THREE.Points(geo, material);
      scene.add(points);
      starLayers.push({ points, material, baseOp: spec.baseOp, phase: Math.random() * 6.28 });
    }

    // two big soft nebula glows drifting very slowly — depth without noise
    const nebulae = [];
    [
      { color: "rgba(124,58,237,0.55)", x: -9, y: 5, scale: 26 },
      { color: "rgba(34,211,238,0.35)", x: 11, y: -6, scale: 22 },
    ].forEach((n) => {
      const mat = new THREE.SpriteMaterial({
        map: makeGlowTexture(n.color), transparent: true, opacity: 0.10,
        depthWrite: false, blending: THREE.AdditiveBlending,
      });
      const sp = new THREE.Sprite(mat);
      sp.position.set(n.x, n.y, -10);
      sp.scale.setScalar(n.scale);
      scene.add(sp);
      nebulae.push({ sprite: sp, mat });
    });

    let mouseX = 0, mouseY = 0;
    window.addEventListener("mousemove", (e) => {
      mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
      mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
    }, { passive: true });

    function resize() {
      // clientWidth/Height can read 0 (or a stale canvas-default 300x150)
      // if called before the very first layout pass has settled — use
      // getBoundingClientRect() (always current) and re-run once more on
      // the next frame as a belt-and-suspenders guard against that race.
      const r = canvas.getBoundingClientRect();
      const w = r.width || window.innerWidth;
      const h = r.height || window.innerHeight;
      if (w === 0 || h === 0) return;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    }
    window.addEventListener("resize", resize);
    resize();
    requestAnimationFrame(resize);

    let raf = null, t = 0;
    function tick() {
      raf = requestAnimationFrame(tick);
      if (tabHidden) return;
      if (!reduceMotion) {
        t += 0.016;
        for (const l of starLayers) {
          l.points.rotation.y += 0.00025;
          l.material.opacity = l.baseOp * (0.75 + 0.25 * Math.sin(t * 0.5 + l.phase));
        }
        camera.position.x += (mouseX * 1.2 - camera.position.x) * 0.02;
        camera.position.y += (-mouseY * 0.8 - camera.position.y) * 0.02;
        camera.lookAt(0, 0, 0);
      }
      renderer.render(scene, camera);
    }
    tick();

    return {
      setThreatLevel(level) {
        // posture now shows as a whisper, not a red sky: the violet nebula
        // warms toward the status colour while the stars stay neutral.
        const colors = { good: 0x3ddc84, warn: 0xf5a524, danger: 0xff4d5e };
        const c = colors[level];
        if (nebulae[0]) {
          nebulae[0].mat.color.setHex(c === undefined ? 0xffffff : c);
          nebulae[0].mat.opacity = c === undefined ? 0.10 : 0.14;
        }
      },
      stop() { if (raf) cancelAnimationFrame(raf); },
    };
  }

  // ---------------------------------------------------------------------
  // Scene 2: 3D health orb
  // ---------------------------------------------------------------------
  function initHealthOrb() {
    const canvas = document.getElementById("healthOrb3d");
    if (!canvas) return null;
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    } catch {
      return null;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 20);
    camera.position.z = 4.2;

    const geo = new THREE.IcosahedronGeometry(1.15, 2);
    const material = new THREE.MeshStandardMaterial({
      color: 0x9a90b3, roughness: 0.35, metalness: 0.15,
      emissive: 0x2a1250, emissiveIntensity: 0.4, flatShading: true,
    });
    const orb = new THREE.Mesh(geo, material);
    scene.add(orb);

    const key = new THREE.PointLight(0xffffff, 22, 12);
    key.position.set(3, 2, 4);
    scene.add(key);
    scene.add(new THREE.AmbientLight(0x2a1250, 0.9));

    function resize() {
      const s = canvas.getBoundingClientRect().width || 84;
      if (s === 0) return;
      renderer.setSize(s, s, false);
      camera.aspect = 1;
      camera.updateProjectionMatrix();
    }
    window.addEventListener("resize", resize);
    resize();
    requestAnimationFrame(resize);

    let raf = null;
    function tick() {
      raf = requestAnimationFrame(tick);
      if (tabHidden) return;
      if (!reduceMotion) orb.rotation.y += 0.004;
      renderer.render(scene, camera);
    }
    tick();

    return {
      setScore(score, level) {
        const colors = { good: 0x3ddc84, warn: 0xf5a524, danger: 0xff4d5e };
        const c = score == null ? 0x9a90b3 : (colors[level] || 0x9a90b3);
        material.color.setHex(c);
        material.emissive.setHex(c);
        material.emissiveIntensity = score == null ? 0.15 : 0.35 + (score / 100) * 0.25;
      },
      stop() { if (raf) cancelAnimationFrame(raf); },
    };
  }

  const ambient = initAmbient();
  const orb = initHealthOrb();
  window.scene3d = { ambient, orb };
})();
