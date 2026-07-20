// Shared inline-SVG icon set — stroke-based, currentColor, matches nav-icon
// style. Keeps every button icon visually consistent instead of ad-hoc SVGs
// scattered across index.html.
const ICONS = {
  play: '<path d="M6 4l14 8-14 8V4z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.34-5.66M20 4v5h-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  download: '<path d="M12 3v12m0 0l-4-4m4 4l4-4M4 19h16" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  eyeOff: '<path d="M3 3l18 18M10.6 10.6a2.5 2.5 0 0 0 3.5 3.5M6.6 6.6C4.5 8 3 10 2 12c1.8 3.6 5.5 7 10 7 1.7 0 3.3-.4 4.7-1.1M9.9 4.2A10.6 10.6 0 0 1 12 4c4.5 0 8.2 3.4 10 7-.6 1.1-1.3 2.2-2.2 3.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  sparkles: '<path d="M12 3l1.6 4.4L18 9l-4.4 1.6L12 15l-1.6-4.4L6 9l4.4-1.6L12 3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M19 15l.7 1.9L21.5 17.6l-1.8.7L19 20.2l-.7-1.9-1.8-.7 1.8-.7L19 15z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>',
  message: '<path d="M4 5h16v11H8l-4 4V5z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>',
  save: '<path d="M5 4h11l3 3v13H5V4z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M8 4v5h7V4M8 20v-6h8v6" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>',
  bell: '<path d="M6 9a6 6 0 1 1 12 0c0 4 1.5 5.5 1.5 5.5H4.5S6 13 6 9z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M9.5 17a2.5 2.5 0 0 0 5 0" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
  mail: '<path d="M4 6h16v12H4V6z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M4 7l8 6 8-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  clock: '<circle cx="12" cy="12" r="8" stroke="currentColor" stroke-width="1.8"/><path d="M12 8v4l3 2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  chevronDown: '<path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  arrowUpRight: '<path d="M7 17L17 7M9 7h8v8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  x: '<path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
  key: '<circle cx="8" cy="15" r="4" stroke="currentColor" stroke-width="1.8"/><path d="M11 12l9-9M17 6l2 2M14 9l2 2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
};

function icon(name, cls = "btn-icon") {
  const body = ICONS[name] || "";
  return `<svg class="${cls}" viewBox="0 0 24 24" fill="none" aria-hidden="true">${body}</svg>`;
}
