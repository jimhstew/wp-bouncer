<?php
/**
 * In-memory source for the dashboard widget statistics.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

use WPBouncer\Log\WidgetStatsSource;

/** Returns what the test sets and records how it was asked. */
final class FakeWidgetSource implements WidgetStatsSource {

	/** @var array<string, array<string, int>> */
	public array $counts = array();

	/** @var array<string, array<string, int>> column => value => count */
	public array $tops = array();

	/** @var array<int, array<string, string>> */
	public array $rows = array();

	/** @var string[] Names of the calls made. */
	public array $calls = array();

	/** @var string The lower bound passed to recent(). */
	public string $recent_since = '';

	/** @var array<int, string> The arguments of the last period_counts() call. */
	public array $period_args = array();

	/** @var array<int, array{string, ?string}> column and action of each top() call. */
	public array $top_calls = array();

	/** {@inheritDoc} */
	public function period_counts( string $since14, string $since7, string $since24, string $since48 ): array {
		$this->calls[]     = 'period_counts';
		$this->period_args = array( $since14, $since7, $since24, $since48 );
		return $this->counts;
	}

	/** {@inheritDoc} */
	public function top( string $column, string $since, int $limit = 10, ?string $action = null ): array {
		$this->calls[]     = 'top';
		$this->top_calls[] = array( $column, $action );
		return array_slice( $this->tops[ $column ] ?? array(), 0, $limit, true );
	}

	/** {@inheritDoc} */
	public function recent( int $limit, array $actions, string $since ): array {
		$this->calls[]      = 'recent';
		$this->recent_since = $since;
		return array_slice( $this->rows, 0, $limit );
	}
}
