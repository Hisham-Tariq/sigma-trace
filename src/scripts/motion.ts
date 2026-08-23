/**
 * Motion helpers, matching the timings used on hishamtariq.com:
 * ease is cubic-bezier(.4,0,.2,1); reveals run 0.7s, staggered children 0.6s
 * with a 60ms step. Everything here is a no-op under prefers-reduced-motion.
 */

const EASE = 'cubic-bezier(.4,0,.2,1)';

export const reducedMotion = () =>
  matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * Scroll reveal. The hidden state lives behind `html.fx-reveal`, which is only
 * set when JS runs, so content is never invisible without it.
 */
export function initReveal() {
  const targets = document.querySelectorAll('.reveal, .reveal-stagger');
  if (reducedMotion() || !('IntersectionObserver' in window)) {
    targets.forEach((t) => t.classList.add('in'));
    return;
  }
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        e.target.classList.add('in');
        io.unobserve(e.target);
      }
    },
    { rootMargin: '0px 0px -8% 0px', threshold: 0.08 },
  );
  targets.forEach((t) => io.observe(t));
}

/**
 * <details> cannot animate its own height, so the open/close is driven here.
 * Delegated from a container because the blocks are re-rendered on every
 * keystroke, which would strip any listeners bound to individual elements.
 */
export function animateDisclosures(container: HTMLElement) {
  container.addEventListener('click', (ev) => {
    const summary = (ev.target as HTMLElement).closest('summary');
    if (!summary) return;
    const details = summary.parentElement as HTMLDetailsElement | null;
    if (!details || !container.contains(details)) return;

    const body = details.querySelector<HTMLElement>('.checks');
    if (!body || reducedMotion()) return; // let the browser do it plainly

    ev.preventDefault();
    if (details.dataset.animating === '1') return;
    details.dataset.animating = '1';

    const finish = () => {
      body.style.height = '';
      body.style.overflow = '';
      delete details.dataset.animating;
    };

    if (details.open) {
      const from = body.scrollHeight;
      body.style.overflow = 'hidden';
      const a = body.animate(
        [{ height: `${from}px`, opacity: 1 }, { height: '0px', opacity: 0 }],
        { duration: 180, easing: EASE },
      );
      a.onfinish = () => { details.open = false; finish(); };
      a.oncancel = finish;
    } else {
      details.open = true;
      const to = body.scrollHeight;
      body.style.overflow = 'hidden';
      const a = body.animate(
        [{ height: '0px', opacity: 0 }, { height: `${to}px`, opacity: 1 }],
        { duration: 220, easing: EASE },
      );
      a.onfinish = finish;
      a.oncancel = finish;
    }
  });
}

/**
 * Re-rendering the whole results panel on every keystroke would flicker if it
 * animated each time. Instead only a *changed* verdict gets a brief pulse.
 */
export function pulseOnChange(el: HTMLElement, key: string) {
  if (el.dataset.lastKey === key) return;
  el.dataset.lastKey = key;
  if (reducedMotion()) return;
  el.animate(
    [
      { transform: 'translateY(-3px)', opacity: 0.55 },
      { transform: 'translateY(0)', opacity: 1 },
    ],
    { duration: 260, easing: EASE },
  );
}
