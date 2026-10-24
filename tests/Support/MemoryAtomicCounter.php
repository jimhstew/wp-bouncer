<?php
/**
 * In-memory implementation of AtomicCounterInterface, for tests.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

use WPBouncer\Storage\AtomicCounterInterface;
use WPBouncer\Support\Clock;

/**
 * Array-backed counter with fixed windows.
 */
final class MemoryAtomicCounter implements AtomicCounterInterface {

	/**
	 * Counters: key => [ 'hits' => int, 'expires' => int ].
	 *
	 * @var array<string, array{hits: int, expires: int}>
	 */
	private array $items = array();

	private Clock $clock;

	/**
	 * @param Clock|null $clock Time source.
	 */
	public function __construct( ?Clock $clock = null ) {
		$this->clock = $clock ?? new Clock();
	}

	/** {@inheritDoc} */
	public function add_or_increment( string $key, int $ttl ): int {
		if ( ! isset( $this->items[ $key ] ) || $this->items[ $key ]['expires'] <= $this->clock->now() ) {
			$this->items[ $key ] = array(
				'hits'    => 0,
				'expires' => $this->clock->now() + max( 1, $ttl ),
			);
		}
		return ++$this->items[ $key ]['hits'];
	}

	/** {@inheritDoc} */
	public function decrement( string $key ): void {
		if ( isset( $this->items[ $key ] ) ) {
			$this->items[ $key ]['hits'] = max( 0, $this->items[ $key ]['hits'] - 1 );
		}
	}

	/** {@inheritDoc} */
	public function get( string $key ): int {
		if ( ! isset( $this->items[ $key ] ) || $this->items[ $key ]['expires'] <= $this->clock->now() ) {
			return 0;
		}
		return $this->items[ $key ]['hits'];
	}

	/** {@inheritDoc} */
	public function delete( string $key ): void {
		unset( $this->items[ $key ] );
	}
}
