<?php
/**
 * Atomic counter on a persistent object cache.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Storage;

defined( 'ABSPATH' ) || exit;

/**
 * Uses wp_cache_add() then wp_cache_incr()/wp_cache_decr(), which are atomic on
 * the Redis and Memcached drop-ins. Only use it when wp_using_ext_object_cache()
 * is true; without a persistent cache the values would not be shared between requests.
 */
final class ObjectCacheCounter implements AtomicCounterInterface {

	public const GROUP = 'wp_bouncer';

	/**
	 * Cache keys are hashed so any logical key is safe.
	 *
	 * @param string $key Logical key.
	 */
	private function name( string $key ): string {
		return 'wpb_ctr_' . md5( $key );
	}

	/**
	 * Count one more event inside a fixed window.
	 *
	 * @param string $key Logical key.
	 * @param int    $ttl Window length in seconds.
	 * @return int The counter after the increment.
	 */
	public function add_or_increment( string $key, int $ttl ): int {
		$name = $this->name( $key );
		$ttl  = max( 1, $ttl );
		// Add is a no-op when the key exists, so the window is set once.
		wp_cache_add( $name, 0, self::GROUP, $ttl );
		$value = wp_cache_incr( $name, 1, self::GROUP );
		if ( false === $value ) {
			// Evicted between the two calls: start a new window.
			wp_cache_set( $name, 1, self::GROUP, $ttl );
			return 1;
		}
		return (int) $value;
	}

	/**
	 * Give one count back (never below zero).
	 *
	 * @param string $key Logical key.
	 */
	public function decrement( string $key ): void {
		// wp_cache_decr() floors at zero.
		wp_cache_decr( $this->name( $key ), 1, self::GROUP );
	}

	/**
	 * Current value inside the window, 0 when missing or expired.
	 *
	 * @param string $key Logical key.
	 */
	public function get( string $key ): int {
		$value = wp_cache_get( $this->name( $key ), self::GROUP, true );
		return is_numeric( $value ) ? max( 0, (int) $value ) : 0;
	}

	/**
	 * Forget a counter.
	 *
	 * @param string $key Logical key.
	 */
	public function delete( string $key ): void {
		wp_cache_delete( $this->name( $key ), self::GROUP );
	}
}
