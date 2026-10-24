<?php
/**
 * In-memory implementation of CounterStoreInterface, for tests.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

use WPBouncer\Storage\CounterStoreInterface;
use WPBouncer\Support\Clock;

/**
 * Array-backed store that lives for one PHP process.
 */
final class MemoryStore implements CounterStoreInterface {

	/**
	 * Stored items: key => [ 'value' => mixed, 'expires' => int ].
	 *
	 * @var array<string, array{value: mixed, expires: int}>
	 */
	private array $items = array();

	private Clock $clock;

	/**
	 * @param Clock|null $clock Time source (defaults to the system clock).
	 */
	public function __construct( ?Clock $clock = null ) {
		$this->clock = $clock ?? new Clock();
	}

	/** @return string[] Every stored key (for tests). */
	public function keys(): array {
		return array_keys( $this->items );
	}

	/** {@inheritDoc} */
	public function get( string $key ) {
		if ( ! isset( $this->items[ $key ] ) ) {
			return null;
		}
		if ( $this->items[ $key ]['expires'] <= $this->clock->now() ) {
			unset( $this->items[ $key ] );
			return null;
		}
		return $this->items[ $key ]['value'];
	}

	/** {@inheritDoc} */
	public function set( string $key, $value, int $ttl ): void {
		$this->items[ $key ] = array(
			'value'   => $value,
			'expires' => $this->clock->now() + max( 1, $ttl ),
		);
	}

	/** {@inheritDoc} */
	public function increment( string $key, int $ttl ): int {
		if ( null === $this->get( $key ) ) {
			$this->set( $key, 1, $ttl );
			return 1;
		}
		$this->items[ $key ]['value'] = (int) $this->items[ $key ]['value'] + 1;
		return $this->items[ $key ]['value'];
	}

	/** {@inheritDoc} */
	public function delete( string $key ): void {
		unset( $this->items[ $key ] );
	}
}
