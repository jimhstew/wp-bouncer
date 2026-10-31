/* WP Bouncer threat map: panel toggle, roving focus, tooltip, show all. Text only; no network, no HTML strings. */
(() => {
'use strict';
const KEY = 'wpb_map:open';
const core = {
	// The stored panel state: '1', '0' or null (anything else is invalid).
	state: raw => raw === '1' || raw === '0' ? raw : null,
	// Next focus index for a key, or null when the key is not handled. dir is -1 in RTL.
	move: (i, key, len, dir) => {
		if (!(len > 0)) return null;
		const d = { ArrowDown: 1, ArrowUp: -1, ArrowRight: dir, ArrowLeft: -dir }[key];
		if (key === 'Home') return 0;
		if (key === 'End') return len - 1;
		return d === undefined ? null : Math.max(0, Math.min(len - 1, i + d));
	},
	// Tooltip position inside the canvas box: above the dot, flipped below near the top, clamped.
	place: (dot, tip, box) => {
		const left = Math.max(0, Math.min(box.width - tip.width, dot.x - tip.width / 2));
		let top = dot.y - dot.r - tip.height - 4;
		if (top < 0) top = dot.y + dot.r + 4;
		return { left, top: Math.max(0, Math.min(box.height - tip.height, top)) };
	}
};
if (typeof module === 'object' && module.exports) { module.exports = core; return; }
const tx = (window.wpBouncerMap || {}).i18n || {};
const root = document.querySelector('.wpb-map');
if (!root) return;
const on = (el, n, f) => el.addEventListener(n, e => { if (e.isTrusted) f(e); });
const ls = (() => { try { return window.localStorage; } catch (e) { return null; } })();
const body = root.querySelector('.wpb-map-body'), btn = root.querySelector('.wpb-map-toggle');

// Panel toggle.
if (btn && body && tx.hide && tx.show) {
	btn.hidden = false;
	const show = open => {
		body.hidden = !open;
		btn.setAttribute('aria-expanded', open ? 'true' : 'false');
		btn.textContent = open ? tx.hide : tx.show;
	};
	let saved = null;
	try {
		const raw = ls && ls.getItem(KEY);
		saved = core.state(raw);
		if (raw != null && saved === null) ls.removeItem(KEY);
	} catch (e) { saved = null; }
	show(saved !== '0');
	on(btn, 'click', () => {
		const open = body.hidden;
		show(open);
		try { if (ls) ls.setItem(KEY, open ? '1' : '0'); } catch (e) { /* storage unavailable */ }
	});
}

// The table gets keyboard access only when it actually scrolls.
const pane = root.querySelector('.wpb-map-top'), cap = pane && pane.querySelector('caption');
const scrollable = () => {
	if (!pane || !cap || pane.scrollHeight <= pane.clientHeight) return;
	pane.tabIndex = 0;
	pane.setAttribute('role', 'region');
	pane.setAttribute('aria-label', cap.textContent);
};
scrollable();

// Show all countries.
const more = root.querySelector('.wpb-map-more'), extra = root.querySelectorAll('tr.wpb-map-extra');
if (more && extra.length && tx.fewer) {
	const label = more.dataset.more || more.textContent;
	more.hidden = false;
	extra.forEach(r => { r.hidden = true; });
	on(more, 'click', () => {
		const open = more.getAttribute('aria-expanded') !== 'true';
		extra.forEach(r => { r.hidden = !open; });
		more.setAttribute('aria-expanded', open ? 'true' : 'false');
		more.textContent = open ? tx.fewer : label;
		scrollable();
	});
}

// Dots: roving focus and tooltip.
const svg = root.querySelector('.wpb-map-dots'), tip = root.querySelector('.wpb-map-tip'), canvas = root.querySelector('.wpb-map-canvas');
if (!svg || !tip || !canvas) return;
const dots = [].slice.call(svg.querySelectorAll('circle[data-cc]'));
const t1 = document.createElement('span'), t2 = document.createElement('span');
t1.className = 'wpb-map-tip-title';
tip.appendChild(t1);
tip.appendChild(document.createElement('br'));
tip.appendChild(t2);
let timer = 0, shown = null;
const dotOf = e => e.target && e.target.closest ? e.target.closest('circle[data-cc]') : null;
const onEsc = e => { if (e.key === 'Escape') hide(); };
const hide = () => {
	clearTimeout(timer);
	tip.hidden = true;
	shown = null;
	document.removeEventListener('keydown', onEsc);
};
const open = dot => {
	clearTimeout(timer);
	if (shown === dot) return;
	t1.textContent = dot.dataset.title || '';
	t2.textContent = dot.dataset.count || '';
	tip.hidden = false;
	if (!shown) document.addEventListener('keydown', onEsc);
	shown = dot;
	const c = canvas.getBoundingClientRect(), d = dot.getBoundingClientRect(), t = tip.getBoundingClientRect();
	const p = core.place({ x: d.left - c.left + d.width / 2, y: d.top - c.top + d.height / 2, r: d.height / 2 }, { width: t.width, height: t.height }, { width: c.width, height: c.height });
	tip.style.left = p.left + 'px';
	tip.style.top = p.top + 'px';
};
const later = () => { clearTimeout(timer); timer = setTimeout(hide, 300); };
on(svg, 'pointerover', e => { const d = dotOf(e); if (d) open(d); });
on(svg, 'pointerout', e => { if (dotOf(e)) later(); });
on(svg, 'focusin', e => { const d = dotOf(e); if (d) open(d); });
on(svg, 'focusout', hide);
on(svg, 'pointerdown', e => { const d = dotOf(e); if (d && e.pointerType === 'touch') open(d); });
on(tip, 'pointerenter', () => clearTimeout(timer));
on(tip, 'pointerleave', later);
on(root, 'pointerdown', e => { if (e.pointerType === 'touch' && !dotOf(e) && !tip.contains(e.target)) hide(); });
on(svg, 'keydown', e => {
	const cur = dots.indexOf(dotOf(e));
	const dir = getComputedStyle(root).direction === 'rtl' ? -1 : 1;
	const next = cur < 0 ? null : core.move(cur, e.key, dots.length, dir);
	if (next === null) return;
	e.preventDefault();
	dots.forEach((d, i) => d.setAttribute('tabindex', i === next ? '0' : '-1'));
	dots[next].focus();
});
})();
