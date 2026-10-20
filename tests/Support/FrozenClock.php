<?php
/**
 * A clock the test controls.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

use WPBouncer\Support\Clock;

/**
 * Time stands still until advance() is called.
 */
final class FrozenClock extends Clock {

	private int $now;

	/**
	 * @param int $now Starting timestamp.
	 */
	public function __construct( int $now = 1700000000 ) {
		$this->now = $now;
	}

	/** {@inheritDoc} */
	public function now(): int {
		return $this->now;
	}

	/**
	 * Move time forward.
	 *
	 * @param int $seconds Seconds.
	 */
	public function advance( int $seconds ): void {
		$this->now += $seconds;
	}
}
