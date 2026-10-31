'use strict';
const test = require('node:test');
const assert = require('node:assert');
const core = require('../../wp-bouncer/assets/threat-map.js');

test('state accepts only 1 and 0', () => {
	assert.strictEqual(core.state('1'), '1');
	assert.strictEqual(core.state('0'), '0');
	for (const v of ['<img src=x onerror=alert(1)>', '2', '', null, undefined]) assert.strictEqual(core.state(v), null);
});

test('move handles keys, direction and bounds', () => {
	assert.strictEqual(core.move(1, 'ArrowDown', 5, 1), 2);
	assert.strictEqual(core.move(1, 'ArrowUp', 5, 1), 0);
	assert.strictEqual(core.move(1, 'ArrowRight', 5, 1), 2);
	assert.strictEqual(core.move(1, 'ArrowLeft', 5, 1), 0);
	assert.strictEqual(core.move(1, 'ArrowRight', 5, -1), 0);
	assert.strictEqual(core.move(1, 'ArrowLeft', 5, -1), 2);
	assert.strictEqual(core.move(1, 'Home', 5, 1), 0);
	assert.strictEqual(core.move(1, 'End', 5, 1), 4);
	assert.strictEqual(core.move(0, 'ArrowUp', 5, 1), 0);
	assert.strictEqual(core.move(4, 'ArrowDown', 5, 1), 4);
	assert.strictEqual(core.move(1, 'a', 5, 1), null);
	assert.strictEqual(core.move(0, 'Home', 0, 1), null);
});

test('place clamps and flips', () => {
	const box = { width: 400, height: 200 }, tip = { width: 100, height: 30 };
	assert.deepStrictEqual(core.place({ x: 200, y: 100, r: 5 }, tip, box), { left: 150, top: 61 });
	assert.strictEqual(core.place({ x: 2, y: 100, r: 5 }, tip, box).left, 0);
	assert.strictEqual(core.place({ x: 399, y: 100, r: 5 }, tip, box).left, 300);
	assert.strictEqual(core.place({ x: 200, y: 10, r: 5 }, tip, box).top, 19);
});
