<?php
/**
 * Read side of the block log used by the dashboard widget.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Log;

defined( 'ABSPATH' ) || exit;

/**
 * What Admin\WidgetStats needs from the log. BlockLog implements it; the unit
 * tests use a fake.
 */
interface WidgetStatsSource {

	/**
	 * Event counts per action over the compared periods, in one query.
	 *
	 * @param string $since14 Start of the 14-day window (UTC datetime).
	 * @param string $since7  Start of the last 7 days.
	 * @param string $since24 Start of the last 24 hours.
	 * @param string $since48 Start of the 24 hours before that.
	 * @return array<string, array{h24: int, h24_prev: int, d7: int, d14: int}> Keyed by action.
	 */
	public function period_counts( string $since14, string $since7, string $since24, string $since48 ): array;

	/**
	 * Counts grouped by a column since a time.
	 *
	 * @param string      $column rule|ip|country|action.
	 * @param string      $since  UTC datetime.
	 * @param int         $limit  Max groups.
	 * @param string|null $action Only this action (null: all except alerts).
	 * @return array<string, int> value => count, largest first.
	 */
	public function top( string $column, string $since, int $limit = 10, ?string $action = null ): array;

	/**
	 * Newest rows: time, IP, rule and action only.
	 *
	 * @param int      $limit   Rows.
	 * @param string[] $actions Actions to include.
	 * @param string   $since   Oldest time to read (UTC datetime), so a sparse action cannot walk the whole table.
	 * @return array<int, array{created_at: string, ip: string, rule: string, action: string}>
	 */
	public function recent( int $limit, array $actions, string $since ): array;
}
