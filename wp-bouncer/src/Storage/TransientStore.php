<?php
/**
 * WordPress transient implementation of CounterStoreInterface.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Storage;

defined( 'ABSPATH' ) || exit;

/**
 * Stores counters, lockouts and bans as transients.
 *
 * Without a persistent object cache, transients live in wp_options, so every
 * increment is a database write. That is fine for login failures. For rate
 * limiting on busy sites, install an object cache (Redis/Memcached), which
 * WordPress then uses for transients automatically.
 *
 * Increments are not atomic. Under heavy concurrency a counter can undercount
 * slightly, which is acceptable for throttling.
 */
final class TransientStore implements CounterStoreInterface {

	private const PREFIX = 'wpb_';

	/**
	 * Transient names are limited to 172 chars, so hash the key.
	 *
	 * @param string $key Logical key.
	 */
	private function name( string $key ): string {
		return self::PREFIX . md5( $key );
	}

	/** {@inheritDoc} */
	public function get( string $key ) {
		$data = get_transient( $this->name( $key ) );
		if ( ! is_array( $data ) || ! array_key_exists( 'v', $data ) ) {
			return null;
		}
		if ( isset( $data['e'] ) && (int) $data['e'] <= time() ) {
			return null;
		}
		return $data['v'];
	}

	/** {@inheritDoc} */
	public function set( string $key, $value, int $ttl ): void {
		$ttl = max( 1, $ttl );
		set_transient(
			$this->name( $key ),
			array(
				'v' => $value,
				'e' => time() + $ttl,
			),
			$ttl
		);
	}

	/** {@inheritDoc} */
	public function increment( string $key, int $ttl ): int {
		$name = $this->name( $key );
		$data = get_transient( $name );
		$now  = time();

		if ( ! is_array( $data ) || ! isset( $data['e'] ) || (int) $data['e'] <= $now ) {
			$this->set( $key, 1, $ttl );
			return 1;
		}

		$data['v'] = (int) $data['v'] + 1;
		// Keep the original window end rather than extending it.
		set_transient( $name, $data, max( 1, (int) $data['e'] - $now ) );
		return $data['v'];
	}

	/** {@inheritDoc} */
	public function delete( string $key ): void {
		delete_transient( $this->name( $key ) );
	}
}
