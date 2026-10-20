<?php
/**
 * Short-lived key/value storage with expiry, used for counters, lockouts and bans.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Storage;

defined( 'ABSPATH' ) || exit;

/**
 * Contract for expiring key/value storage.
 *
 * Production uses TransientStore (which uses the object cache when one is
 * installed); the unit tests use an in-memory store.
 */
interface CounterStoreInterface {

	/**
	 * Fetch a value.
	 *
	 * @param string $key Key.
	 * @return mixed|null Null when missing or expired.
	 */
	public function get( string $key );

	/**
	 * Store a value for $ttl seconds.
	 *
	 * @param string $key   Key.
	 * @param mixed  $value Value (must be serialisable).
	 * @param int    $ttl   Lifetime in seconds (>= 1).
	 */
	public function set( string $key, $value, int $ttl ): void;

	/**
	 * Increment a counter inside a fixed window.
	 *
	 * The window starts at the first increment and is NOT extended by later
	 * increments, so "5 failures in 15 minutes" behaves as expected.
	 *
	 * @param string $key Key.
	 * @param int    $ttl Window length in seconds.
	 * @return int The counter value after incrementing.
	 */
	public function increment( string $key, int $ttl ): int;

	/**
	 * Remove a key.
	 *
	 * @param string $key Key.
	 */
	public function delete( string $key ): void;
}
