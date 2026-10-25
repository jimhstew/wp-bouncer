/* WP Bouncer column resize */
(() => {
'use strict';
const K = new Map([['Home', 'min'], ['End', 'max'], ['Escape', 'reset'], ['ArrowRight', 10], ['ArrowLeft', -10]]);
const sum = (a, f) => a.reduce((s, x, i) => s + f(x, i), 0);
const core = {
	parse: (raw, min, max) => typeof raw === 'string' && /^\d{1,4}$/.test(raw) ? Math.max(min, Math.min(max, +raw)) : null,
	key: (t, c) => (t === 'log' || t === 'traffic') && typeof c === 'string' && /^[a-z0-9_]{1,32}$/.test(c) ? 'wpb_cols:' + t + ':' + c : null,
	// data-wpb-min: 1-4 digits, at least 1, else the default of 60.
	min: raw => typeof raw === 'string' && /^\d{1,4}$/.test(raw) ? Math.max(1, +raw) : 60,
	// A stored width, or null. Anything invalid is removed. Any failure of the store gives null.
	read: (store, key, min, max) => {
		try {
			const raw = key === null || !store ? null : store.getItem(key), n = core.parse(raw, min, max);
			if (raw != null && n === null) store.removeItem(key);
			return n;
		} catch (e) { return null; }
	},
	// Remove this table's keys (exact prefix) from a Storage-like object. Never clear().
	reset: (store, table) => {
		const prefix = core.key(table, 'x') && core.key(table, 'x').slice(0, -1), keys = [];
		if (!prefix || !store) return;
		try {
			for (let i = store.length - 1; i >= 0; i--) keys.push(store.key(i));
			keys.filter(k => typeof k === 'string' && k.startsWith(prefix)).forEach(k => store.removeItem(k));
		} catch (e) { /* storage unavailable */ }
	},
	step: (k, shift, dir) => typeof K.get(k) === 'number' ? K.get(k) * (shift ? 5 : 1) * dir : K.get(k) ?? null,
	fit: (ws, mins, st, budget) => {
		const w = ws.map((x, i) => Math.max(mins[i], Math.round(st[i] == null ? x : st[i])));
		let over = sum(w, x => x) - budget;
		w.map((x, i) => i).sort((a, b) => (st[a] != null) - (st[b] != null)).forEach(i => {
			const r = Math.max(0, Math.min(w[i] - mins[i], over));
			w[i] -= r;
			over -= r;
		});
		return w;
	}
};
if (typeof module === 'object' && module.exports) { module.exports = core; return; }
const { i18n: tx, table: tn } = window.wpBouncerCols || {};
const on = (el, n, f) => el.addEventListener(n, e => { if (e.isTrusted) f(e); });
const root = document.querySelector('.wp-bouncer'), tbl = root && root.querySelector('table.wp-list-table');
if ((tn !== 'log' && tn !== 'traffic') || !tbl || !tx) return;
const mq = matchMedia('(max-width: 782px)'), btn = root.querySelector('.wpb-cols-reset'), body = document.body;
if (!btn) return;
let dir = 1, items = [], drag = null, budget = 0, raf = 0;
const ls = (() => { try { return window.localStorage; } catch (e) { return null; } })();
const kk = th => core.key(tn, th.dataset.wpbCol);
const ths = [].filter.call(tbl.querySelectorAll('thead th'), kk);
const min = th => core.min(th.dataset.wpbMin);
const hd = th => th.querySelector('.wpb-col-handle');
const S = (op, k, v) => { try { return localStorage[op + 'Item'](k, v); } catch (e) { return null; } };
const max = it => Math.max(it.min, budget - sum(items, i => i === it ? 0 : i.w));
const aria = (el, a) => Object.keys(a).forEach(k => el.setAttribute('aria-' + k, a[k]));
const sync = () => items.forEach(it => aria(hd(it.th), { valuemin: it.min, valuemax: max(it), valuenow: it.w, valuetext: tx.px.replace('%d', () => it.w) }));
const put = (it, w, save) => {
	it.w = Math.round(Math.max(it.min, Math.min(max(it), w)));
	it.th.style.width = it.w + 'px';
	if (save) S('set', kk(it.th), String(it.w));
	sync();
};
const stop = cancel => {
	if (drag && cancel === true) put(drag.it, drag.w, false);
	else if (drag && drag.moved) put(drag.it, drag.it.w, true);
	drag = null;
	body.classList.remove('wpb-col-dragging');
};
const freeze = th => {
	if (!tbl.classList.contains('wpb-cols-fixed')) apply(true);
	return items.find(i => i.th === th);
};
const make = th => {
	const h = document.createElement('span');
	h.className = 'wpb-col-handle';
	h.tabIndex = 0;
	th.appendChild(h);
	aria(h, { orientation: 'vertical', label: tx.resize.replace('%s', () => th.dataset.wpbLabel || '') });
	h.setAttribute('role', 'separator');
	on(h, 'pointerdown', e => {
		const it = e.isTrusted && e.button === 0 && freeze(th);
		if (!it) return;
		e.preventDefault();
		e.stopPropagation();
		h.focus();
		drag = { it, x: e.clientX, w: it.w, moved: false };
		h.setPointerCapture(e.pointerId);
		body.classList.add('wpb-col-dragging');
	});
	on(h, 'pointermove', e => { if (drag) { drag.moved = true; put(drag.it, drag.w + (e.clientX - drag.x) * dir, false); } });
	on(h, 'pointerup', () => stop());
	on(h, 'lostpointercapture', () => stop());
	on(h, 'pointercancel', () => stop(true));
	on(h, 'click', e => { e.stopPropagation(); e.preventDefault(); });
	on(h, 'dblclick', () => { S('removeItem', kk(th)); apply(); });
	on(h, 'keydown', e => {
		if (drag) {
			if (e.key === 'Escape') { e.preventDefault(); stop(true); }
			return;
		}
		const s = e.ctrlKey || e.altKey || e.metaKey ? null : core.step(e.key, e.shiftKey, dir);
		if (s === null) return;
		e.preventDefault();
		e.stopPropagation();
		if (s === 'reset') { S('removeItem', kk(th)); return apply(); }
		const it = freeze(th);
		if (it) put(it, s === 'min' ? it.min : s === 'max' ? max(it) : it.w + s, true);
	});
};
const show = list => ths.forEach(th => {
	hd(th).hidden = !list.includes(th);
	th.classList.toggle('wpb-has-handle', list.includes(th));
});
const apply = force => {
	const vis = ths.filter(th => th.getClientRects().length), fill = vis.pop();
	tbl.classList.remove('wpb-cols-fixed');
	items = [];
	ths.forEach(th => { th.style.width = ''; if (!hd(th)) make(th); });
	btn.hidden = mq.matches;
	tbl.classList.toggle('wpb-cols-on', !mq.matches);
	if (mq.matches || !fill) return show([]);
	dir = getComputedStyle(tbl).direction === 'rtl' ? -1 : 1;
	const st = vis.map(th => core.read(ls, kk(th), min(th), 9999));
	budget = tbl.clientWidth - min(fill);
	const w = core.fit(vis.map(th => th.getBoundingClientRect().width), vis.map(min), st, budget);
	vis.forEach((th, i) => { items.push({ th, min: min(th), w: w[i] }); });
	if (force === true || st.some(n => n !== null)) {
		items.forEach(it => { it.th.style.width = it.w + 'px'; });
		tbl.classList.add('wpb-cols-fixed');
	}
	show(vis);
	sync();
};
on(btn, 'click', () => {
	try { core.reset(ls, tn); } catch (e) { /* storage blocked */ }
	apply();
});
const later = () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => apply()); };
on(window, 'resize', later);
on(mq, 'change', later);
on(document, 'change', e => { if (e.target.matches && e.target.matches('.hide-column-tog')) later(); });
apply();
})();
