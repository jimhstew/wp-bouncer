'use strict';
// Logic tests for assets/columns.js (WPB-10b). Run with: node --test tests/js/*.test.js
const test = require('node:test');
const assert = require('node:assert');
const core = require('../../wp-bouncer/assets/columns.js');

test('parse accepts 1-4 digit integers and clamps them', () => {
	assert.strictEqual(core.parse('240', 60, 800), 240);
	assert.strictEqual(core.parse('30', 60, 800), 60);
	assert.strictEqual(core.parse('9999', 60, 800), 800);
	assert.strictEqual(core.parse('0', 44, 800), 44);
	assert.strictEqual(core.parse('0060', 44, 800), 60);
});

test('parse rejects hostile and malformed stored values', () => {
	const bad = [
		'<img src=x onerror=alert(1)>', '-5', '1e9', 'NaN', '12px;background:url(//x)', '{', '', ' 12', '12 ', '12\n',
		'1.5', '12345', '+7', '0x10', 'Infinity', null, undefined, 240, {}, [], ['12'],
	];
	bad.forEach(v => assert.strictEqual(core.parse(v, 60, 800), null, String(v)));
});

test('key builds only for the two tables and safe column ids', () => {
	assert.strictEqual(core.key('log', 'request'), 'wpb_cols:log:request');
	assert.strictEqual(core.key('traffic', 'user_agent'), 'wpb_cols:traffic:user_agent');
	assert.strictEqual(core.key('log', 'a'.repeat(32)), 'wpb_cols:log:' + 'a'.repeat(32));
	assert.strictEqual(core.key('log', 'Request'), null);
	assert.strictEqual(core.key('log', 'a-b'), null);
	assert.strictEqual(core.key('log', 'a'.repeat(33)), null);
	assert.strictEqual(core.key('log', ''), null);
	assert.strictEqual(core.key('log', undefined), null);
	assert.strictEqual(core.key('log', 'a:b'), null);
	assert.strictEqual(core.key('rules', 'request'), null);
	assert.strictEqual(core.key('', 'request'), null);
	assert.strictEqual(core.key(undefined, 'request'), null);
});

test('step in LTR: arrows widen to the right, Shift is 5x', () => {
	assert.strictEqual(core.step('ArrowRight', false, 1), 10);
	assert.strictEqual(core.step('ArrowRight', true, 1), 50);
	assert.strictEqual(core.step('ArrowLeft', false, 1), -10);
	assert.strictEqual(core.step('ArrowLeft', true, 1), -50);
});

test('step in RTL: the arrow directions mirror', () => {
	assert.strictEqual(core.step('ArrowRight', false, -1), -10);
	assert.strictEqual(core.step('ArrowRight', true, -1), -50);
	assert.strictEqual(core.step('ArrowLeft', false, -1), 10);
	assert.strictEqual(core.step('ArrowLeft', true, -1), 50);
});

test('step maps Home, End and Escape the same in both directions', () => {
	[1, -1].forEach(dir => [false, true].forEach(shift => {
		assert.strictEqual(core.step('Home', shift, dir), 'min');
		assert.strictEqual(core.step('End', shift, dir), 'max');
		assert.strictEqual(core.step('Escape', shift, dir), 'reset');
	}));
});

test('step ignores every other key, including object property names', () => {
	['a', 'Enter', 'Tab', 'ArrowUp', 'ArrowDown', '', 'constructor', '__proto__', 'hasOwnProperty', null, undefined, 5]
		.forEach(k => assert.strictEqual(core.step(k, false, 1), null, String(k)));
});

test('fit leaves widths alone when they fit, and uses stored over measured', () => {
	assert.deepStrictEqual(core.fit([100, 100, 100], [60, 60, 60], [null, null, null], 300), [100, 100, 100]);
	assert.deepStrictEqual(core.fit([999, 80], [60, 60], [150, null], 400), [150, 80]);
	assert.deepStrictEqual(core.fit([100.4], [60], [null], 500), [100]);
});

test('fit raises anything under its minimum', () => {
	assert.deepStrictEqual(core.fit([20, 100], [44, 60], [null, null], 500), [44, 100]);
	assert.deepStrictEqual(core.fit([100], [60], [10], 500), [60]);
});

test('fit shrinks unstored columns before stored ones', () => {
	assert.deepStrictEqual(core.fit([100, 100, 100], [60, 60, 60], [null, null, null], 250), [60, 90, 100]);
	assert.deepStrictEqual(core.fit([100, 100, 100], [60, 60, 60], [200, null, null], 300), [180, 60, 60]);
});

test('fit never goes below the minimums, even with no room', () => {
	assert.deepStrictEqual(core.fit([100, 100, 100], [60, 60, 60], [200, null, null], 0), [60, 60, 60]);
	assert.deepStrictEqual(core.fit([100, 200], [44, 60], [null, 500], -50), [44, 60]);
});

test('fit does not change its inputs', () => {
	const ws = [100, 100], st = [200, null];
	core.fit(ws, [60, 60], st, 100);
	assert.deepStrictEqual(ws, [100, 100]);
	assert.deepStrictEqual(st, [200, null]);
});

test('min reads data-wpb-min: 1-4 digits, at least 1, else 60', () => {
	assert.strictEqual(core.min('44'), 44);
	assert.strictEqual(core.min('60'), 60);
	assert.strictEqual(core.min('0'), 1);
	assert.strictEqual(core.min('9999'), 9999);
	['', '12345', '-5', '1e3', '<x>', ' 5', null, undefined, 44, {}].forEach(v => assert.strictEqual(core.min(v), 60, String(v)));
});

class FakeStore {
	constructor(init) { this.d = new Map(Object.entries(init || {})); }
	get length() { return this.d.size; }
	key(i) { const k = [...this.d.keys()][i]; return k === undefined ? null : k; }
	getItem(k) { return this.d.has(k) ? this.d.get(k) : null; }
	setItem(k, v) { this.d.set(k, String(v)); }
	removeItem(k) { this.d.delete(k); }
}

class ThrowingStore {
	get length() { throw new Error('blocked'); }
	key() { throw new Error('blocked'); }
	getItem() { throw new Error('blocked'); }
	setItem() { throw new Error('blocked'); }
	removeItem() { throw new Error('blocked'); }
}

test('read returns a clamped width and leaves a missing key alone', () => {
	const store = new FakeStore({ 'wpb_cols:log:ip': '200', 'wpb_cols:log:rule': '5', 'wpb_cols:log:action': '9000' });
	assert.strictEqual(core.read(store, 'wpb_cols:log:ip', 60, 800), 200);
	assert.strictEqual(core.read(store, 'wpb_cols:log:rule', 60, 800), 60);
	assert.strictEqual(core.read(store, 'wpb_cols:log:action', 60, 800), 800);
	assert.strictEqual(core.read(store, 'wpb_cols:log:none', 60, 800), null);
	assert.strictEqual(store.length, 3);
});

test('read removes hostile seeded values and gives null', () => {
	['<img src=x onerror=alert(1)>', '-5', '1e9', 'NaN', '12px;background:url(//x)', '{', '', '12345', '1.5'].forEach(v => {
		const store = new FakeStore({ 'wpb_cols:log:ip': v, 'wpb_cols:log:keep': '100' });
		assert.strictEqual(core.read(store, 'wpb_cols:log:ip', 60, 800), null, v);
		assert.strictEqual(store.getItem('wpb_cols:log:ip'), null, 'removed: ' + v);
		assert.strictEqual(store.getItem('wpb_cols:log:keep'), '100');
	});
});

test('read gives null for a null key and for a store that throws on every method', () => {
	assert.strictEqual(core.read(new FakeStore({ a: '100' }), null, 60, 800), null);
	assert.strictEqual(core.read(new ThrowingStore(), 'wpb_cols:log:ip', 60, 800), null);
});

test('reset removes only the exact table prefix', () => {
	const seed = {
		'wpb_cols:log:ip': '100', 'wpb_cols:log:request': '300',
		'wpb_cols:traffic:request': '250', 'wpb_cols:logx:ip': '90',
		'wpb_cols:log': '1', 'other': 'x', 'wpb_cols:': '2', 'xwpb_cols:log:ip': '3',
	};
	const store = new FakeStore(seed);
	core.reset(store, 'log');
	assert.deepStrictEqual([...store.d.keys()].sort(), ['other', 'wpb_cols:', 'wpb_cols:log', 'wpb_cols:logx:ip', 'wpb_cols:traffic:request', 'xwpb_cols:log:ip']);
	core.reset(store, 'traffic');
	assert.strictEqual(store.getItem('wpb_cols:traffic:request'), null);
	assert.strictEqual(store.getItem('wpb_cols:logx:ip'), '90');
});

test('reset ignores an unknown table and survives a store that throws', () => {
	['rules', 'logx', '', undefined, null].forEach(t => {
		const store = new FakeStore({ 'wpb_cols:log:ip': '100', 'wpb_cols:rules:ip': '100' });
		core.reset(store, t);
		assert.strictEqual(store.length, 2, String(t));
	});
	assert.doesNotThrow(() => core.reset(new ThrowingStore(), 'log'));
});

test('a null store (storage blocked) reads as empty and resets without throwing', () => {
	assert.strictEqual(core.read(null, 'wpb_cols:log:ip', 60, 800), null);
	assert.strictEqual(core.read(undefined, 'wpb_cols:log:ip', 60, 800), null);
	assert.doesNotThrow(() => core.reset(null, 'log'));
});
