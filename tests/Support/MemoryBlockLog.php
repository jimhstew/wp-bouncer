<?php
/**
 * In-memory block log for assertions.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

use WPBouncer\Log\BlockLogInterface;

/**
 * Collects entries in an array.
 */
final class MemoryBlockLog implements BlockLogInterface {

	/** @var array<int, array<string, string>> */
	public array $entries = array();

	/** {@inheritDoc} */
	public function record( array $entry ): int {
		$this->entries[] = $entry;
		return count( $this->entries );
	}
}
