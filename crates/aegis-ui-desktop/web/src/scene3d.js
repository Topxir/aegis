'use strict';
/* 3D layer: one canvas (#gl) under the UI. An object follows its .obj3d
   anchor in the DOM every frame (spring-smoothed), a swarm of 480 cubes
   morphs one object into another, particles fill the background.
   Three.js comes from jsdelivr; without it (or without WebGL) the app still
   works and anchors get a flat line drawing. */
const AegisScene = (() => {
  const URL3 = '/vendor/three.module.min.js';
  const SV = d => `<svg viewBox="0 0 24 24" aria-hidden="true">${d}</svg>`;
  const FLAT = {
    shield: SV('<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6z"/><path d="M12 9.2a1.6 1.6 0 0 1 .7 3l.5 3.3h-2.4l.5-3.3a1.6 1.6 0 0 1 .7-3z"/>'),
    rings: SV('<circle cx="9" cy="12" r="5.5"/><circle cx="15" cy="12" r="5.5"/>'),
    ash: SV('<circle cx="12" cy="12" r="7" stroke-dasharray="1.6 2.4"/>'),
    cube: SV('<path d="M12 3.5l7.5 4.2v8.6L12 20.5l-7.5-4.2V7.7zM4.5 7.7L12 12l7.5-4.3M12 12v8.5"/>'),
  };
  const want = { name: null, anchor: null };
  let pmode = store.get('particles', 'dust'), prog = 0, failed = false, g3 = null, resting = false;
  function flat(anchor, name) {
    if (!anchor) return;
    anchor.classList.add('flat');
    anchor.innerHTML = name && FLAT[name] ? FLAT[name] : '';
  }
  const ready = (async () => {
    try {
      const probe = document.createElement('canvas');
      if (!(probe.getContext('webgl2') || probe.getContext('webgl'))) throw new Error('no webgl');
      const THREE = await import(URL3);
      g3 = build(THREE);
      g3.particles(pmode);
      if (want.name) g3.show(want.name, want.anchor, { assemble: true });
      g3.progress(prog);
      if (resting) g3.rest(0);
      return true;
    } catch (e) {
      failed = true;
      if (want.name) flat(want.anchor, want.name);
      return false;
    }
  })();
  return {
    ready,
    get live() { return !!g3; },
    show(name, anchor, o = {}) {
      want.name = name; want.anchor = anchor; resting = false;
      if (g3) g3.show(name, anchor, o); else if (failed) flat(anchor, name);
    },
    scatter() { want.name = null; want.anchor = null; if (g3) g3.scatter(); },
    /* nothing of the scene can be seen (opaque panes cover it): stop drawing after ms;
       the next show() brings it back */
    rest(ms = 0) { resting = true; if (g3) g3.rest(ms); },
    particles(m) { pmode = m; if (g3) g3.particles(m); },
    progress(p) { prog = p; if (g3) g3.progress(p); },
    pulse() { if (g3) g3.pulse(); },
    snapshot() { return g3 ? g3.snapshot() : null; },
  };

  function build(THREE) {
    const canvas = document.getElementById('gl');
    const LITE = Math.min(screen.width, screen.height) < 600 || /Android|iPhone/.test(navigator.userAgent);
    const renderer = new THREE.WebGLRenderer({ canvas, antialias: !LITE, alpha: true, powerPreference: LITE ? 'default' : 'high-performance' });
    renderer.setClearColor(0x000000, 0);
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.05;
    const scene = new THREE.Scene();
    const FOV = 35, CZ = 10, N = LITE ? 300 : 480, RIM = 0.9;
    const camera = new THREE.PerspectiveCamera(FOV, 1, 0.1, 80);
    camera.position.z = CZ;
    let W = 1, H = 1, K = 0.01;

    // environment: a dark room, soft boxes, a faint red strip low on the left (the rim)
    const envScene = new THREE.Scene();
    envScene.add(new THREE.Mesh(new THREE.BoxGeometry(30, 30, 30), new THREE.MeshBasicMaterial({ color: 0x030304, side: THREE.BackSide })));
    const panel = (w, hh, hexv, k, x, y, z) => {
      const m = new THREE.Mesh(new THREE.PlaneGeometry(w, hh), new THREE.MeshBasicMaterial({ color: new THREE.Color(hexv).multiplyScalar(k), side: THREE.DoubleSide }));
      m.position.set(x, y, z); m.lookAt(0, 0, 0); envScene.add(m);
      return m;
    };
    panel(9, 3, 0xffffff, 4, 0, 8, 4);
    panel(3, 9, 0xdde2ff, 1.6, -8, 1, 3);
    panel(3, 7, 0xffffff, 1, 8, 0, -3);
    const strip = panel(7, 1.6, 0xff1f3d, 0.8, -5, -7, 2);
    const pmrem = new THREE.PMREMGenerator(renderer);
    scene.environment = pmrem.fromScene(envScene, 0.04).texture;
    // the cube is flat metal: a face turned to the strip mirrors it whole and the cube goes red,
    // so the cube gets the same room without the strip (the rim light still edges it)
    strip.visible = false;
    const envCool = pmrem.fromScene(envScene, 0.04).texture;
    strip.visible = true;
    pmrem.dispose();
    const keyL = new THREE.DirectionalLight(0xffffff, 1.4); keyL.position.set(3, 5, 6);
    const rimL = new THREE.DirectionalLight(0xff2a44, RIM); rimL.position.set(-5, -4, -3);
    scene.add(keyL, rimL, new THREE.AmbientLight(0xffffff, 0.08));

    const C = { g1: new THREE.Color(0x2a2b30), g2: new THREE.Color(0x4a4b52), bone: new THREE.Color(0xcfd0d6), hot: new THREE.Color(0xff4d62), dim: new THREE.Color(0x161619) };
    const pick = r => (r < 0.012 ? C.hot : r < 0.14 ? C.bone : r < 0.42 ? C.g2 : C.g1);
    const M = {
      chrome: new THREE.MeshPhysicalMaterial({ color: 0xd6d7dd, metalness: 1, roughness: 0.2, clearcoat: 0.4, clearcoatRoughness: 0.18 }),
      gun: new THREE.MeshPhysicalMaterial({ color: 0x34353b, metalness: 1, roughness: 0.28, clearcoat: 0.6, clearcoatRoughness: 0.2 }),
      ink: new THREE.MeshPhysicalMaterial({ color: 0x0a0a0c, metalness: 0.5, roughness: 0.28, clearcoat: 1, clearcoatRoughness: 0.1 }),
      glow: new THREE.MeshBasicMaterial({ color: new THREE.Color(0xc3122b).multiplyScalar(1.15), toneMapped: false }),
      cells: () => new THREE.MeshPhysicalMaterial({ color: 0xffffff, metalness: 0.88, roughness: 0.3, clearcoat: 0.5, clearcoatRoughness: 0.2 }),
    };
    const glowBase = M.glow.color.clone();

    const v3 = new THREE.Vector3(), dummy = new THREE.Object3D(), qI = new THREE.Quaternion();
    const rnd = (a, b) => a + Math.random() * (b - a);
    const unit = () => { const u = rnd(-1, 1), th = rnd(0, Math.PI * 2), s = Math.sqrt(1 - u * u); return new THREE.Vector3(s * Math.cos(th), u, s * Math.sin(th)); };
    const easeOut = x => 1 - Math.pow(1 - x, 3);
    const easeIO = x => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);
    const smooth = (a, b, x) => { const q = clamp((x - a) / (b - a), 0, 1); return q * q * (3 - 2 * q); };
    const stepS = (s, dt) => { if (reduced) { s.snap(); return; } const n = Math.ceil(dt / 0.004) || 1; for (let i = 0; i < n; i++) s.step(dt / n); if (s.rest) s.snap(); };

    // ── objects: root (anchor position, size) → spin (idle, parallax, drag) → body (appear, breath)
    const objs = {};
    function base(name, idle) {
      const root = new THREE.Group(), spin = new THREE.Group(), body = new THREE.Group();
      root.add(spin); spin.add(body); scene.add(root); root.visible = false;
      return { name, root, spin, body, idle, samples: new Float32Array(N * 3), tick: null, anchor: null, vis: false,
        a: new Spring(0, 170, 0.8), px: new Spring(0, 300, 0.92), py: new Spring(0, 300, 0.92), ps: new Spring(0, 300, 0.92) };
    }
    function shieldPath(p, sc, dy) {
      const P = (x, y) => [x * sc, y * sc + dy];
      p.moveTo(...P(0, 0.84));
      p.bezierCurveTo(...P(0.28, 0.98), ...P(0.6, 0.96), ...P(0.82, 0.86));
      p.bezierCurveTo(...P(0.86, 0.2), ...P(0.7, -0.5), ...P(0, -1));
      p.bezierCurveTo(...P(-0.7, -0.5), ...P(-0.86, 0.2), ...P(-0.82, 0.86));
      p.bezierCurveTo(...P(-0.6, 0.96), ...P(-0.28, 0.98), ...P(0, 0.84));
      return p;
    }
    function makeShield() {
      const o = base('shield', t => [Math.sin(t * 0.31) * 0.07, Math.sin(t * 0.45) * 0.34, 0]);
      const outer = shieldPath(new THREE.Shape(), 1, 0);
      outer.holes.push(shieldPath(new THREE.Path(), 0.8, 0.04));
      const rimG = new THREE.ExtrudeGeometry(outer, { depth: 0.2, bevelEnabled: true, bevelThickness: 0.07, bevelSize: 0.05, bevelSegments: 5, curveSegments: 48 });
      rimG.translate(0, 0, -0.1);
      const ins = shieldPath(new THREE.Shape(), 0.795, 0.04);
      const kh = new THREE.Path(), cy = 0.14, r = 0.12;
      kh.moveTo(-0.045, cy + r * Math.sin(4.3286));
      kh.absarc(0, cy, r, 4.3286, -1.1864, true);
      kh.lineTo(0.075, -0.3); kh.lineTo(-0.075, -0.3); kh.closePath();
      ins.holes.push(kh);
      const insG = new THREE.ExtrudeGeometry(ins, { depth: 0.1, bevelEnabled: true, bevelThickness: 0.02, bevelSize: 0.015, bevelSegments: 2, curveSegments: 48 });
      insG.translate(0, 0, -0.05);
      const plate = new THREE.Mesh(new THREE.PlaneGeometry(0.3, 0.56), M.glow);
      plate.position.set(0, -0.03, -0.085);
      o.body.add(new THREE.Mesh(rimG, M.chrome), new THREE.Mesh(insG, M.ink), plate);
      const poly = outer.getPoints(96).map(p => [p.x, p.y]);
      const inside = (x, y) => {
        let c = false;
        for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
          const [xi, yi] = poly[i], [xj, yj] = poly[j];
          if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) c = !c;
        }
        return c;
      };
      for (let i = 0; i < N; i++) {
        let x, y, z;
        const q = Math.random();
        if (q < 0.2) { const p = poly[(Math.random() * poly.length) | 0]; x = p[0]; y = p[1]; z = rnd(-0.15, 0.15); }
        else { do { x = rnd(-0.86, 0.86); y = rnd(-1, 0.98); } while (!inside(x, y)); z = q < 0.85 ? 0.13 : rnd(-0.15, 0.15); }
        o.samples.set([x, y, z], i * 3);
      }
      return o;
    }
    function makeRings() {
      const o = base('rings', t => [0.5 + Math.sin(t * 0.3) * 0.12, t * 0.42, 0.18]);
      const f = 0.58, R = f, rr = 0.22 * f;
      const g = new THREE.TorusGeometry(R, rr, 40, 140);
      const a = new THREE.Mesh(g, M.chrome); a.position.x = -0.5 * f;
      const b = new THREE.Mesh(g, M.gun); b.position.x = 0.5 * f; b.rotation.x = Math.PI / 2;
      o.body.add(a, b);
      for (let i = 0; i < N; i++) {
        const u = rnd(0, Math.PI * 2), w = rnd(0, Math.PI * 2);
        let x = (R + rr * Math.cos(w)) * Math.cos(u), y = (R + rr * Math.cos(w)) * Math.sin(u), z = rr * Math.sin(w);
        if (i % 2) { const yy = y; y = -z; z = yy; x += 0.5 * f; } else x -= 0.5 * f;
        o.samples.set([x, y, z], i * 3);
      }
      return o;
    }
    function makeAsh() {
      const o = base('ash', t => [0.32, t * 0.14, 0]);
      const n = 460, im = new THREE.InstancedMesh(new THREE.BoxGeometry(1, 1, 1), M.cells(), n);
      im.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
      const home = [], st = [], baseC = [], ga = Math.PI * (3 - Math.sqrt(5)), tmp = new THREE.Color();
      for (let i = 0; i < n; i++) {
        const y = 1 - (i + 0.5) / n * 2, r = Math.sqrt(1 - y * y), th = ga * i;
        const p = new THREE.Vector3(Math.cos(th) * r, y, Math.sin(th) * r).multiplyScalar(0.86);
        home.push(p);
        const c = pick(0.04 + Math.random() * 0.96).clone();
        baseC.push(c); im.setColorAt(i, c);
        st.push({ m: 0, t0: 0, next: rnd(0.4, 14), dur: rnd(1.4, 2.2), s: rnd(0.06, 0.085),
          dir: p.clone().normalize().add(new THREE.Vector3(rnd(-0.3, 0.3), rnd(0.4, 0.9), rnd(-0.3, 0.3))).normalize(),
          rot: new THREE.Euler(rnd(0, 3), rnd(0, 3), rnd(0, 3)) });
      }
      o.body.add(im);
      for (let i = 0; i < N; i++) { const p = home[i % n]; o.samples.set([p.x, p.y, p.z], i * 3); }
      o.tick = t => {
        for (let i = 0; i < n; i++) {
          const s = st[i], p = home[i];
          let sc = s.s, x = p.x, y = p.y, z = p.z;
          if (s.m === 0 && t > s.next && !reduced) { s.m = 1; s.t0 = t; }
          if (s.m === 1) {
            const u = (t - s.t0) / s.dur;
            if (u >= 1) { s.m = 2; s.t0 = t; sc = 0; im.setColorAt(i, baseC[i]); }
            else {
              const d = u * 0.9;
              x += s.dir.x * d + Math.sin(t * 3 + i) * 0.04 * u; y += s.dir.y * d + u * u * 0.5; z += s.dir.z * d;
              sc = s.s * (1 - u);
              tmp.copy(baseC[i]).lerp(C.hot, Math.max(0, 1 - u * 2.2) * 0.9);
              if (u > 0.45) tmp.lerp(C.dim, (u - 0.45) / 0.55);
              im.setColorAt(i, tmp);
            }
          } else if (s.m === 2) {
            const u = (t - s.t0) / 0.7;
            if (u >= 1) { s.m = 0; s.next = t + rnd(5, 16); } else sc = s.s * easeOut(u);
          }
          dummy.position.set(x, y, z); dummy.rotation.copy(s.rot); dummy.scale.setScalar(Math.max(1e-4, sc));
          dummy.updateMatrix(); im.setMatrixAt(i, dummy.matrix);
        }
        im.instanceMatrix.needsUpdate = true;
        if (im.instanceColor) im.instanceColor.needsUpdate = true;
      };
      return o;
    }
    function makeCube() {
      const o = base('cube', t => [0.52, 0.62 + t * 0.3, 0]);
      const n = 64, mat = M.cells();
      mat.metalness = 0.7; mat.envMapIntensity = 0.7; mat.envMap = envCool;
      const im = new THREE.InstancedMesh(new THREE.BoxGeometry(0.36, 0.36, 0.36), mat, n);
      im.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
      const cells = [];
      for (let i = 0; i < n; i++) {
        const gx = i % 4, gy = (i >> 2) % 4, gz = i >> 4;
        cells.push({ home: new THREE.Vector3((gx - 1.5) * 0.42, (gy - 1.5) * 0.42, (gz - 1.5) * 0.42),
          far: unit().multiplyScalar(rnd(1.3, 2.4)),
          q: new THREE.Quaternion().setFromEuler(new THREE.Euler(rnd(-3, 3), rnd(-3, 3), rnd(-3, 3))),
          a: 0, thr: gy / 4 * 0.78 + Math.random() * 0.2 });
        im.setColorAt(i, Math.random() < 0.12 ? C.bone : Math.random() < 0.5 ? C.g2 : C.g1);
      }
      o.body.add(im);
      for (let i = 0; i < N; i++) { const c = cells[i % n].home; o.samples.set([c.x + rnd(-0.17, 0.17), c.y + rnd(-0.17, 0.17), c.z + rnd(-0.17, 0.17)], i * 3); }
      o.p = prog;
      o.tick = (t, dt) => {
        for (let i = 0; i < n; i++) {
          const c = cells[i], target = o.p >= c.thr ? 1 : 0;
          c.a = reduced ? target : clamp(c.a + (target ? dt : -dt) / 0.6, 0, 1);
          const e = easeIO(c.a);
          dummy.position.lerpVectors(c.far, c.home, e);
          dummy.quaternion.slerpQuaternions(c.q, qI, e);
          dummy.scale.setScalar(0.55 + 0.45 * e);
          dummy.updateMatrix(); im.setMatrixAt(i, dummy.matrix);
        }
        im.instanceMatrix.needsUpdate = true;
        mat.emissive.copy(C.bone).multiplyScalar(flash * 0.3);
      };
      return o;
    }
    const MAKE = { shield: makeShield, rings: makeRings, ash: makeAsh, cube: makeCube };
    const get = name => objs[name] || (objs[name] = MAKE[name]());

    // ── swarm: 480 cubes on quadratic bezier arcs ──
    const swarm = new THREE.InstancedMesh(new THREE.BoxGeometry(1, 1, 1), M.cells(), N);
    swarm.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    swarm.frustumCulled = false; swarm.visible = false;
    const sw = [];
    for (let i = 0; i < N; i++) { sw.push({ d: Math.random() * 0.3, ax: unit(), sp: rnd(2, 7), arc: unit(), k: rnd(0.7, 1.25) }); swarm.setColorAt(i, pick(Math.random())); }
    scene.add(swarm);
    const A = new Float32Array(N * 3), B = new Float32Array(N * 3), P = new Float32Array(N * 3);
    let job = null, cur = null, flash = 0;

    function worldSamples(o, out) {
      place(o, performance.now() / 1000);
      o.root.updateMatrixWorld(true);
      const m = o.spin.matrixWorld;
      for (let i = 0; i < N; i++) v3.fromArray(o.samples, i * 3).applyMatrix4(m).toArray(out, i * 3);
    }
    function startJob(kind, from, to) {
      const s0 = job ? job.s0 : from ? from.ps.x * 0.06 : to.ps.x * 0.06;
      if (job && swarm.visible) A.set(P);
      else if (from) worldSamples(from, A);
      else for (let i = 0; i < N; i++) v3.copy(unit()).multiplyScalar(rnd(2.6, 5) * to.ps.x).add(new THREE.Vector3(to.px.x, to.py.x, 0)).toArray(A, i * 3);
      if (from) { from.a.snap(0); from.root.visible = false; }
      let span = 0.5 * (to ? to.ps.x : from.ps.x);
      if (kind === 'scatter') {
        const cx = from.px.x, cy = from.py.x;
        for (let i = 0; i < N; i++) {
          v3.set(A[i * 3] - cx, A[i * 3 + 1] - cy, A[i * 3 + 2]).normalize().add(unit().multiplyScalar(0.6)).normalize().multiplyScalar(rnd(2, 4.5) * from.ps.x);
          B[i * 3] = A[i * 3] + v3.x; B[i * 3 + 1] = A[i * 3 + 1] + v3.y; B[i * 3 + 2] = A[i * 3 + 2] + v3.z;
        }
        span = 0.4 * from.ps.x;
      } else if (from) span += 0.25 * Math.hypot(to.px.x - from.px.x, to.py.x - from.py.x);
      if (to) to.a.snap(0);
      job = { kind, t0: performance.now(), to, F: kind === 'scatter' ? 0.95 : 0.85, s0, span, shown: false };
      swarm.visible = true;
    }
    function runJob(now) {
      const e = (now - job.t0) / 1000, to = job.to;
      let m = null;
      if (to) { place(to, now / 1000); to.root.updateMatrixWorld(true); m = to.spin.matrixWorld; }
      const s1 = to ? to.ps.x * 0.06 : job.s0;
      let all = true;
      for (let i = 0; i < N; i++) {
        const s = sw[i], u = clamp((e - s.d) / job.F, 0, 1);
        if (u < 1) all = false;
        const w = job.kind === 'scatter' ? easeOut(u) : easeIO(u);
        let bx, by, bz;
        if (m) { v3.fromArray(to.samples, i * 3).applyMatrix4(m); bx = v3.x; by = v3.y; bz = v3.z; }
        else { bx = B[i * 3]; by = B[i * 3 + 1]; bz = B[i * 3 + 2]; }
        const ax = A[i * 3], ay = A[i * 3 + 1], az = A[i * 3 + 2];
        const cx = (ax + bx) / 2 + s.arc.x * job.span, cy = (ay + by) / 2 + s.arc.y * job.span, cz = (az + bz) / 2 + s.arc.z * job.span;
        const k0 = (1 - w) * (1 - w), k1 = 2 * (1 - w) * w, k2 = w * w;
        const x = k0 * ax + k1 * cx + k2 * bx, y = k0 * ay + k1 * cy + k2 * by, z = k0 * az + k1 * cz + k2 * bz;
        P[i * 3] = x; P[i * 3 + 1] = y; P[i * 3 + 2] = z;
        let sc = (job.s0 + (s1 - job.s0) * w) * s.k;
        sc *= job.kind === 'scatter' ? 1 - smooth(0.35, 1, u) : 1 - smooth(0.78, 1, u);
        dummy.position.set(x, y, z);
        dummy.quaternion.setFromAxisAngle(s.ax, e * s.sp);
        dummy.scale.setScalar(Math.max(1e-4, sc));
        dummy.updateMatrix(); swarm.setMatrixAt(i, dummy.matrix);
      }
      swarm.instanceMatrix.needsUpdate = true;
      if (to && !job.shown && e >= 0.55) job.shown = true;
      if (all) { swarm.visible = false; job = null; }
    }

    // ── anchors, parallax, drag ──
    const par = { x: new Spring(0, 60, 0.9), y: new Spring(0, 60, 0.9) }, ptr = { x: 0, y: 0 };
    const drag = { x: new Spring(0, 70, 0.35), y: new Spring(0, 70, 0.35), on: false };
    const hooked = new WeakSet();
    function follow(o, snap) {
      const el = o.anchor;
      let vis = !!(el && el.isConnected && el.offsetParent !== null), r = null;
      if (vis) { r = el.getBoundingClientRect(); vis = r.width > 4 && r.height > 4 && r.bottom > 0 && r.top < H && r.right > 0 && r.left < W; }
      if (vis) {
        o.px.to = (r.left + r.width / 2 - W / 2) * K;
        o.py.to = -(r.top + r.height / 2 - H / 2) * K;
        o.ps.to = Math.min(r.width, r.height) * K * 0.5 * 0.8;
        if (snap) { o.px.snap(); o.py.snap(); o.ps.snap(); }
      }
      o.vis = vis;
    }
    function place(o, t) {
      o.root.position.set(o.px.x, o.py.x, 0);
      o.root.scale.setScalar(Math.max(1e-4, o.ps.x));
      const [ix, iy, iz] = o.idle(reduced ? 1.4 : t);
      o.spin.rotation.set(ix + par.y.x * 0.28 + drag.y.x, iy + par.x.x * 0.45 + drag.x.x, iz);
      const br = reduced ? 1 : 1 + Math.sin(t * 1.3) * 0.012;
      o.body.scale.setScalar(Math.max(1e-4, o.a.x * br * (1 + flash * 0.04)));
      o.root.visible = o.a.x > 0.003;
    }
    function hook(el) {
      if (!el || hooked.has(el)) return;
      hooked.add(el);
      let x0 = 0, y0 = 0, bx = 0, by = 0;
      el.addEventListener('pointerdown', e => {
        if (!el.classList.contains('hit') || reduced) return;
        drag.on = true; x0 = e.clientX; y0 = e.clientY; bx = drag.x.x; by = drag.y.x;
        el.setPointerCapture(e.pointerId); el.style.cursor = 'grabbing'; wake();
      });
      el.addEventListener('pointermove', e => {
        if (!drag.on) return;
        drag.x.snap(bx + (e.clientX - x0) * 0.012);
        drag.y.snap(clamp(by + (e.clientY - y0) * 0.008, -0.6, 0.6));
      });
      const up = () => { if (!drag.on) return; drag.on = false; drag.x.to = 0; drag.y.to = 0; el.style.cursor = ''; };
      el.addEventListener('pointerup', up);
      el.addEventListener('pointercancel', up);
    }
    addEventListener('pointermove', e => {
      if (e.pointerType !== 'mouse') return;
      ptr.x = clamp(e.clientX / W * 2 - 1, -1, 1); ptr.y = clamp(e.clientY / H * 2 - 1, -1, 1);
    }, { passive: true });

    // ── particles: ~700 additive points, rain as lines ──
    const pf = (() => {
      const n = LITE ? 380 : 700;
      const pos = new Float32Array(n * 3), vel = new Float32Array(n * 3), seed = new Float32Array(n), size = new Float32Array(n);
      const g = new THREE.BufferGeometry();
      const pa = new THREE.BufferAttribute(pos, 3); pa.setUsage(THREE.DynamicDrawUsage);
      g.setAttribute('position', pa);
      g.setAttribute('aSeed', new THREE.BufferAttribute(seed, 1));
      const sa = new THREE.BufferAttribute(size, 1); g.setAttribute('aSize', sa);
      const mat = new THREE.ShaderMaterial({
        uniforms: { uColor: { value: new THREE.Color() }, uPR: { value: 1 }, uAlpha: { value: 0.5 }, uTime: { value: 0 }, uTw: { value: 0.35 } },
        vertexShader: 'attribute float aSize;attribute float aSeed;uniform float uPR;varying float vSeed;void main(){vec4 mv=modelViewMatrix*vec4(position,1.);gl_Position=projectionMatrix*mv;gl_PointSize=aSize*uPR*(10./max(.5,-mv.z));vSeed=aSeed;}',
        fragmentShader: 'uniform vec3 uColor;uniform float uAlpha;uniform float uTime;uniform float uTw;varying float vSeed;void main(){vec2 c=gl_PointCoord-.5;float d=length(c);if(d>.5)discard;float a=smoothstep(.5,0.,d);float tw=1.-uTw+uTw*sin(uTime*2.2+vSeed*40.);gl_FragColor=vec4(uColor*a*uAlpha*tw,0.);}',
        transparent: true, premultipliedAlpha: true, depthWrite: false, blending: THREE.AdditiveBlending,
      });
      const points = new THREE.Points(g, mat);
      points.frustumCulled = false; points.renderOrder = -1; points.visible = false;
      const lpos = new Float32Array(n * 6);
      const lg = new THREE.BufferGeometry();
      const la = new THREE.BufferAttribute(lpos, 3); la.setUsage(THREE.DynamicDrawUsage);
      lg.setAttribute('position', la);
      const lines = new THREE.LineSegments(lg, new THREE.LineBasicMaterial({ color: 0xc8c9d0, transparent: true, opacity: 0.16, blending: THREE.AdditiveBlending, depthWrite: false }));
      lines.frustumCulled = false; lines.renderOrder = -1; lines.visible = false;
      scene.add(points, lines);
      const Z0 = -6, Z1 = 3;
      let mode = 'none', hw = 6, hh = 4;
      const CONF = {
        dust: { c: [0.5, 0.51, 0.56], a: 0.55, s: [3, 6], tw: 0.35 },
        snow: { c: [0.8, 0.81, 0.86], a: 0.5, s: [4, 8], tw: 0.1 },
        embers: { c: [1, 0.26, 0.32], a: 0.75, s: [3, 6.5], tw: 0.55 },
        orbit: { c: [0.7, 0.71, 0.77], a: 0.5, s: [2.5, 5], tw: 0.25 },
      };
      function bounds() { hh = Math.tan(FOV * Math.PI / 360) * (CZ - Z0) * 1.05; hw = hh * camera.aspect; }
      function spawn(i, first) {
        const x = rnd(-hw, hw), z = rnd(Z0, Z1);
        let y = rnd(-hh, hh);
        if (mode === 'snow' && !first) y = hh + rnd(0, 1);
        if (mode === 'embers' && !first) y = -hh - rnd(0, 1);
        pos[i * 3] = x; pos[i * 3 + 1] = y; pos[i * 3 + 2] = z;
        if (mode === 'dust') { vel[i * 3] = rnd(-0.06, 0.06); vel[i * 3 + 1] = rnd(-0.04, 0.05); vel[i * 3 + 2] = rnd(-0.03, 0.03); }
        if (mode === 'snow') { vel[i * 3] = 0; vel[i * 3 + 1] = -rnd(0.18, 0.5); vel[i * 3 + 2] = 0; }
        if (mode === 'embers') { vel[i * 3] = rnd(-0.05, 0.05); vel[i * 3 + 1] = rnd(0.25, 0.8); vel[i * 3 + 2] = 0; }
        if (mode === 'orbit') { vel[i * 3] = rnd(1.8, Math.max(2.4, hw * 0.95)); vel[i * 3 + 1] = rnd(0, Math.PI * 2); vel[i * 3 + 2] = rnd(0.04, 0.12) * (Math.random() < 0.5 ? 1 : -1) / Math.sqrt(vel[i * 3] / 2); }
        if (mode === 'rain') { vel[i * 3] = -rnd(5, 9); vel[i * 3 + 1] = rnd(0.25, 0.6); if (!first) pos[i * 3 + 1] = hh + rnd(0, 2); }
      }
      function set(m) {
        mode = CONF[m] || m === 'rain' ? m : 'none';
        points.visible = !!CONF[mode]; lines.visible = mode === 'rain';
        if (CONF[mode]) {
          const c = CONF[mode];
          mat.uniforms.uColor.value.setRGB(c.c[0], c.c[1], c.c[2]);
          mat.uniforms.uAlpha.value = c.a; mat.uniforms.uTw.value = c.tw;
          for (let i = 0; i < n; i++) { seed[i] = Math.random(); size[i] = rnd(c.s[0], c.s[1]); }
          g.attributes.aSeed.needsUpdate = true; sa.needsUpdate = true;
        }
        for (let i = 0; i < n; i++) spawn(i, true);
        tick(0, 0);
      }
      function tick(t, dt) {
        mat.uniforms.uTime.value = t;
        mat.uniforms.uPR.value = renderer.getPixelRatio();
        if (mode === 'none') return;
        if (mode === 'rain') {
          for (let i = 0; i < n; i++) {
            const vy = vel[i * 3], L = vel[i * 3 + 1];
            pos[i * 3 + 1] += vy * dt; pos[i * 3] += vy * 0.12 * dt;
            if (pos[i * 3 + 1] < -hh - 1) spawn(i, false);
            const x = pos[i * 3], y = pos[i * 3 + 1], z = pos[i * 3 + 2], k = L / Math.hypot(1, 0.12);
            lpos.set([x, y, z, x + 0.12 * k, y + k, z], i * 6);
          }
          la.needsUpdate = true;
          return;
        }
        for (let i = 0; i < n; i++) {
          if (mode === 'orbit') {
            const r = vel[i * 3]; vel[i * 3 + 1] += vel[i * 3 + 2] * dt;
            const a = vel[i * 3 + 1];
            pos[i * 3] = Math.cos(a) * r; pos[i * 3 + 1] = Math.sin(a) * r * 0.32 + (seed[i] - 0.5) * 0.5; pos[i * 3 + 2] = Math.sin(a) * r * 0.9 - 2;
            continue;
          }
          pos[i * 3] += (vel[i * 3] + (mode === 'snow' ? Math.sin(t * 0.8 + seed[i] * 30) * 0.12 : 0)) * dt;
          pos[i * 3 + 1] += vel[i * 3 + 1] * dt;
          pos[i * 3 + 2] += vel[i * 3 + 2] * dt;
          const y = pos[i * 3 + 1], x = pos[i * 3];
          if (mode === 'snow' && y < -hh - 0.5) spawn(i, false);
          else if (mode === 'embers' && y > hh + 0.5) spawn(i, false);
          else if (mode === 'dust') {
            if (x > hw) pos[i * 3] -= 2 * hw; if (x < -hw) pos[i * 3] += 2 * hw;
            if (y > hh) pos[i * 3 + 1] -= 2 * hh; if (y < -hh) pos[i * 3 + 1] += 2 * hh;
          }
        }
        pa.needsUpdate = true;
      }
      return { set, tick, bounds, get mode() { return mode; } };
    })();

    // ── loop: sleeps when nothing moves ──
    let running = false, last = 0, hold = 0, covered = false, coverT = 0;
    function uncover() {
      clearTimeout(coverT);
      if (covered) { covered = false; canvas.style.visibility = ''; }
    }
    function wake() {
      hold = performance.now() + 450;
      if (running || covered) return;
      running = true; last = performance.now();
      requestAnimationFrame(frame);
    }
    function frame(now) {
      if (document.hidden || covered) { running = false; return; }
      const dt = Math.min(0.05, Math.max(0, (now - last) / 1000)), t = now / 1000;
      last = now;
      stepS(par.x, dt); stepS(par.y, dt);
      par.x.to = ptr.x; par.y.to = ptr.y;
      if (!drag.on) { stepS(drag.x, dt); stepS(drag.y, dt); }
      flash *= Math.exp(-dt * 3.2);
      M.glow.color.copy(glowBase).multiplyScalar(1 + flash * 2.4);
      // flat metal faces mirror the red rim whole; the cube keeps it as a thin edge only
      { const rt = cur && cur.name === 'cube' ? 0.2 : RIM; rimL.intensity = reduced ? rt : rimL.intensity + (rt - rimL.intensity) * Math.min(1, dt * 6); }
      if (cur) follow(cur, false);
      for (const k in objs) {
        const o = objs[k];
        o.a.to = o === cur && o.vis && (!job || job.to !== o || job.shown) ? 1 : 0;
        stepS(o.a, dt); stepS(o.px, dt); stepS(o.py, dt); stepS(o.ps, dt);
        place(o, t);
        if (o.root.visible && o.tick) o.tick(t, dt);
      }
      if (job) runJob(now);
      if (!reduced) pf.tick(t, dt);
      renderer.render(scene, camera);
      const busy = now < hold || (!reduced && (cur || job || pf.mode !== 'none' || drag.on || Object.values(objs).some(o => o.root.visible)));
      if (busy) requestAnimationFrame(frame); else running = false;
    }
    function resize() {
      W = innerWidth; H = innerHeight;
      renderer.setPixelRatio(Math.min(devicePixelRatio || 1, LITE ? 1.25 : 1.5));
      renderer.setSize(W, H, false);
      camera.aspect = W / Math.max(1, H);
      camera.updateProjectionMatrix();
      K = 2 * Math.tan(FOV * Math.PI / 360) * CZ / Math.max(1, H);
      pf.bounds();
      wake();
    }
    addEventListener('resize', resize);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) wake(); });
    motionSubs.add(() => { pf.set(pf.mode); wake(); });
    canvas.addEventListener('webglcontextlost', e => { e.preventDefault(); running = false; });
    canvas.addEventListener('webglcontextrestored', () => wake());
    resize();

    return {
      show(name, anchor, o = {}) {
        uncover();
        if (anchor) { anchor.classList.remove('flat'); hook(anchor); }
        if (!name || !MAKE[name]) { cur = null; wake(); return; }
        const next = get(name);
        next.anchor = anchor;
        if (cur === next) { wake(); return; }
        follow(next, true);
        if (!reduced && cur && o.morph && cur.vis && cur.a.x > 0.4) startJob('morph', cur, next);
        else if (!reduced && o.assemble && next.vis) startJob('assemble', null, next);
        cur = next;
        wake();
      },
      scatter() {
        if (!cur) return;
        if (!reduced && cur.vis && cur.a.x > 0.4) startJob('scatter', cur, null);
        cur = null;
        wake();
      },
      rest(ms) {
        clearTimeout(coverT);
        coverT = setTimeout(() => { covered = true; canvas.style.visibility = 'hidden'; }, ms);
      },
      particles(m) { pf.set(m); wake(); },
      progress(p) { if (objs.cube) objs.cube.p = p; wake(); },
      pulse() { flash = reduced ? 0 : 1; wake(); },
      snapshot() {
        try { renderer.render(scene, camera); return canvas.toDataURL('image/png'); } catch (e) { return null; }
      },
    };
  }
})();
