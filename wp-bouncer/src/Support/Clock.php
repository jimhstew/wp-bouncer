<?php
/**
 * Wall clock abstraction so time-based logic can be tested deterministically.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Returns the current Unix timestamp. Tests substitute a frozen clock.
 */
class Clock {

	/**
	 * Current Unix timestamp in seconds.
	 */
	public function now(): int {
		return time();
	}
}
