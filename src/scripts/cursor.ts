/**
 * "Crosshair Probe" cursor, ported from hishamtariq.com's site.js.
 *
 * Desktop pointers only, skipped under prefers-reduced-motion, and gated on
 * html.fx-cursor so the real cursor is never hidden unless this is running.
 */

const pad = (n: number) => String(Math.max(0, Math.round(n))).padStart(4, '0');

export function initCursor() {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  if (matchMedia('(pointer: coarse)').matches) return;

  const reticle = document.getElementById('cursor-reticle');
  const readout = document.getElementById('cursor-readout');
  if (!reticle || !readout) return;

  document.documentElement.classList.add('fx-cursor');

  let x = -100;
  let y = -100;
  let frame = 0;
  let mode = '';
  let press = 1;

  document.addEventListener(
    'pointermove',
    (e) => {
      x = e.clientX;
      y = e.clientY;
      const t = e.target as Element | null;
      const interactive = t?.closest?.('a, button, [role="button"], [role="option"], [data-cursor], label, summary');
      const text = !interactive && t?.closest?.('input, textarea, [contenteditable]');
      const next = interactive ? 'link' : text ? 'text' : '';
      if (next === mode) return;

      mode = next;
      reticle.classList.toggle('is-link', mode === 'link');
      reticle.classList.toggle('is-text', mode === 'text');
      readout.classList.toggle('is-hidden', mode === 'text');
      if (mode === 'link' && interactive) {
        readout.textContent =
          interactive.getAttribute('data-cursor') ||
          (interactive.matches('a[href^="http"]') ? 'VISIT ↗'
            : interactive.matches('a') ? 'OPEN →'
            : interactive.matches('[role="option"]') ? 'PICK'
            : 'RUN');
      }
    },
    { passive: true },
  );

  document.addEventListener('pointerdown', () => { press = 0.85; });
  document.addEventListener('pointerup', () => { press = 1; });
  document.addEventListener('mouseleave', () => {
    reticle.style.opacity = '0';
    readout.style.opacity = '0';
  });
  document.addEventListener('mouseenter', () => {
    reticle.style.opacity = '1';
    readout.style.opacity = '1';
  });

  const loop = () => {
    // The press scale is composed AFTER the translate so it scales in place;
    // a standalone `scale` property would scale the translation too.
    reticle.style.transform = `translate3d(${x}px, ${y}px, 0) scale(${press})`;
    readout.style.transform = `translate3d(${x + 18}px, ${y + 18}px, 0)`;
    if (mode === '' && (frame = (frame + 1) % 2) === 0) {
      readout.textContent = `x:${pad(x)} y:${pad(y)}`;
    }
    requestAnimationFrame(loop);
  };
  requestAnimationFrame(loop);
}
