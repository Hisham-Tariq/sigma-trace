/**
 * A listbox that can actually animate.
 *
 * A native <select> cannot: the browser draws its popup outside the page, so no
 * CSS reaches it. This replaces it with markup we own, and keeps the parts that
 * make a native select worth using — full keyboard control, correct ARIA roles,
 * and focus returning where it came from.
 */

export interface DropdownOption {
  value: string;
  label: string;
}

export class Dropdown {
  readonly el: HTMLDivElement;
  private button: HTMLButtonElement;
  private list: HTMLUListElement;
  private options: DropdownOption[] = [];
  private activeIndex = -1;
  private open = false;
  private onChange: (value: string) => void;
  private labelId: string;

  constructor(mount: HTMLElement, labelId: string, onChange: (value: string) => void) {
    this.onChange = onChange;
    this.labelId = labelId;

    this.el = document.createElement('div');
    this.el.className = 'dd';

    this.button = document.createElement('button');
    this.button.type = 'button';
    this.button.className = 'dd-btn';
    this.button.setAttribute('aria-haspopup', 'listbox');
    this.button.setAttribute('aria-expanded', 'false');
    this.button.setAttribute('aria-labelledby', `${labelId} dd-value`);
    this.button.innerHTML = '<span class="dd-value" id="dd-value"></span><span class="dd-caret" aria-hidden="true"></span>';

    this.list = document.createElement('ul');
    this.list.className = 'dd-list';
    this.list.setAttribute('role', 'listbox');
    this.list.setAttribute('aria-labelledby', labelId);
    this.list.hidden = true;

    this.el.append(this.button, this.list);
    mount.append(this.el);

    this.button.addEventListener('click', () => (this.open ? this.close() : this.openList()));
    this.button.addEventListener('keydown', (e) => this.onButtonKey(e));
    this.list.addEventListener('keydown', (e) => this.onListKey(e));
    this.list.addEventListener('click', (e) => {
      const li = (e.target as HTMLElement).closest('li');
      if (li) this.commit(Number(li.dataset.index));
    });

    document.addEventListener('click', (e) => {
      if (this.open && !this.el.contains(e.target as Node)) this.close(false);
    });
  }

  setOptions(options: DropdownOption[]) {
    this.options = options;
    this.list.innerHTML = options
      .map(
        (o, i) =>
          `<li role="option" id="dd-opt-${i}" data-index="${i}" aria-selected="false" tabindex="-1">${escapeHtml(o.label)}</li>`,
      )
      .join('');
    if (options.length) this.setValue(options[0].value, false);
  }

  get value(): string {
    return this.activeIndex >= 0 ? this.options[this.activeIndex].value : '';
  }

  setValue(value: string, fire = true) {
    const i = this.options.findIndex((o) => o.value === value);
    if (i < 0) return;
    this.activeIndex = i;
    const valueEl = this.button.querySelector('.dd-value')!;
    valueEl.textContent = this.options[i].label;
    this.list.querySelectorAll('li').forEach((li, n) => {
      li.setAttribute('aria-selected', String(n === i));
    });
    if (fire) this.onChange(this.options[i].value);
  }

  private commit(index: number) {
    if (Number.isNaN(index)) return;
    this.setValue(this.options[index].value);
    this.close();
  }

  private openList() {
    if (this.open || !this.options.length) return;
    this.open = true;
    this.list.hidden = false;
    this.button.setAttribute('aria-expanded', 'true');
    this.el.classList.add('is-open');
    // Force a reflow so the transition has a start value to animate from.
    // requestAnimationFrame would be the usual trick, but it does not fire in a
    // background tab — which left the list open and invisible.
    void this.list.offsetHeight;
    this.el.classList.add('is-shown');
    this.focusOption(this.activeIndex >= 0 ? this.activeIndex : 0);
  }

  private close(returnFocus = true) {
    if (!this.open) return;
    this.open = false;
    this.button.setAttribute('aria-expanded', 'false');
    this.el.classList.remove('is-shown');

    const done = () => {
      if (this.open) return; // reopened mid-transition
      this.list.hidden = true;
      this.el.classList.remove('is-open');
    };
    const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) done();
    else this.list.addEventListener('transitionend', done, { once: true });
    // Belt and braces: if the transition never fires, still tidy up.
    setTimeout(done, 260);

    if (returnFocus) this.button.focus();
  }

  private focusOption(i: number) {
    const items = this.list.querySelectorAll<HTMLLIElement>('li');
    if (!items.length) return;
    const n = Math.max(0, Math.min(i, items.length - 1));
    items.forEach((li) => li.classList.remove('is-active'));
    items[n].classList.add('is-active');
    items[n].focus();
    this.list.setAttribute('aria-activedescendant', `dd-opt-${n}`);
  }

  private currentFocusIndex(): number {
    const active = this.list.querySelector('li.is-active') as HTMLLIElement | null;
    return active ? Number(active.dataset.index) : this.activeIndex;
  }

  private onButtonKey(e: KeyboardEvent) {
    if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) {
      e.preventDefault();
      this.openList();
    }
  }

  private onListKey(e: KeyboardEvent) {
    const last = this.options.length - 1;
    const cur = this.currentFocusIndex();
    switch (e.key) {
      case 'ArrowDown': e.preventDefault(); this.focusOption(Math.min(cur + 1, last)); break;
      case 'ArrowUp':   e.preventDefault(); this.focusOption(Math.max(cur - 1, 0)); break;
      case 'Home':      e.preventDefault(); this.focusOption(0); break;
      case 'End':       e.preventDefault(); this.focusOption(last); break;
      case 'Enter':
      case ' ':         e.preventDefault(); this.commit(cur); break;
      case 'Escape':    e.preventDefault(); this.close(); break;
      case 'Tab':       this.close(false); break;
    }
  }
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
