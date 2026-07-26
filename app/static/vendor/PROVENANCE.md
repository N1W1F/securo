# Vendored third-party files

## three/ (ES module build + addons)

- Source: `https://unpkg.com/three@0.160.0/build/three.module.js`
  and `https://unpkg.com/three@0.160.0/examples/jsm/**` for the addons.
- Version: three.js r160
- License: MIT (Three.js Authors, 2010-2023)
- Fetched once at development time (2026-07-21/26), vendored locally, never
  fetched over the network at app runtime. Served same-origin (`'self'`) —
  fully compliant with this app's CSP (`script-src 'self'`), no CDN dependency.
- Used for: the live 3D agent scene (`pipeline3d.js`) and the ambient
  starfield / health orb (`scene3d.js`). Both import this single copy.
- **Local modification:** the addons under `three/addons/` ship with bare
  specifiers (`from 'three'`). Resolving those in a browser needs an inline
  `<script type="importmap">`, which our CSP (`script-src 'self'`, no
  `'unsafe-inline'`) blocks. Each addon's import was therefore rewritten to a
  relative path (`from '../../three.module.js'`). No other changes.
- Contents:
  - `three/three.module.js`
  - `three/addons/postprocessing/{EffectComposer,RenderPass,ShaderPass,MaskPass,Pass,UnrealBloomPass,OutputPass}.js`
  - `three/addons/shaders/{CopyShader,LuminosityHighPassShader,OutputShader}.js`
- To update: re-download from `https://unpkg.com/three@<version>/…`, re-apply
  the bare-specifier rewrite, review the diff, and re-test both 3D scenes
  manually (no automated coverage for WebGL rendering).

### Removed: `three.min.js` (legacy UMD build)

`scene3d.js` originally ran as a classic script against the UMD
`three.min.js`, so the app shipped **two** complete copies of Three.js
(654 KB UMD + 1295 KB ESM) and parsed both at every launch. `scene3d.js` was
converted to an ES module importing the same `three.module.js` as
`pipeline3d.js`, and the UMD build was deleted.
