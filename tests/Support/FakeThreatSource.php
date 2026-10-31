<?php
/**
 * In-memory source for the threat map.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

use WPBouncer\Log\ThreatMapSource;

/** Returns what the test sets and records how it was asked. */
final class FakeThreatSource implements ThreatMapSource {

	/** @var array<string, int>|null Rows to return (null: a database error). */
	public ?array $rows = array();

	/** @var array<int, array{array<string, string>, string, string}> Arguments of each call. */
	public array $calls = array();

	/** @var callable|null Called before each answer (tests use it to act mid-build). */
	public $on_call = null;

	/** {@inheritDoc} */
	public function threats_by_country( array $filters, string $since, string $until ): ?array {
		$this->calls[] = array( $filters, $since, $until );
		if ( null !== $this->on_call ) {
			( $this->on_call )();
		}
		return $this->rows;
	}
}
