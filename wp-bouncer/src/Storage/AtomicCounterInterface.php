<?php
/**
 * Counters whose increment is atomic across parallel requests.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Storage;

defined( 'ABSPATH' ) || exit;

/**
 * Contract for the login-attempt counter (RT-08).
 *
 * Separate from CounterStoreInterface, whose increment is a read-modify-write.
 * Implementations: ObjectCacheCounter (persistent object cache) and
 * TableCounter (the {prefix}bouncer_counters table).
 */
interface AtomicCounterInterface {

	/**
	 * Count one more event inside a fixed window.
	 *
	 * The window starts at the first call and later calls don't extend it.
	 *
	 * @param string $key Logical key.
	 * @param int    $ttl Window length in seconds (>= 1).
	 * @return int The counter after the increment (>= 1). Parallel callers each get a
	 *             value; no caller is told a value lower than the number of calls
	 *             that completed before it.
	 */
	public function add_or_increment( string $key, int $ttl ): int;

	/**
	 * Give one count back (never below zero).
	 *
	 * @param string $key Logical key.
	 */
	public function decrement( string $key ): void;

	/**
	 * Current value inside the window, 0 when missing or expired.
	 *
	 * @param string $key Logical key.
	 */
	public function get( string $key ): int;

	/**
	 * Forget a counter.
	 *
	 * @param string $key Logical key.
	 */
	public function delete( string $key ): void;
}
