<?php
/**
 * BlockLog SQL against a real database.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Log;

use WPBouncer\Log\BlockLog;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Log\BlockLog
 */
final class BlockLogTest extends IntegrationTestCase {

	/** @var BlockLog */
	private $log;

	public function set_up() {
		parent::set_up();
		global $wpdb;
		$this->log = new BlockLog( $wpdb );
	}

	/**
	 * Insert a row with an explicit time (record() always stamps "now").
	 *
	 * @param array<string, string> $row     Columns.
	 * @param int                   $seconds_ago Age.
	 */
	private function seed( array $row, int $seconds_ago = 0 ): int {
		global $wpdb;
		$id = $this->log->record( $row );
		$this->assertGreaterThan( 0, $id );
		if ( $seconds_ago ) {
			$wpdb->update( $this->log->table(), array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - $seconds_ago ) ), array( 'id' => $id ) );
		}
		return $id;
	}

	public function test_table_name_uses_the_prefix(): void {
		global $wpdb;
		$this->assertSame( $wpdb->prefix . 'bouncer_log', $this->log->table() );
	}

	public function test_record_stores_a_normalised_row_with_utc_time(): void {
		global $wpdb;
		$id = $this->log->record(
			array(
				'ip'         => '198.51.100.4',
				'country'    => 'DE',
				'rule'       => 'waf',
				'action'     => 'blocked',
				'reason'     => "SQL\x00 injection",
				'method'     => 'post',
				'uri'        => '/?s=1',
				'user_agent' => 'curl/8',
			)
		);
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->log->table()} WHERE id = %d", $id ), ARRAY_A ); // phpcs:ignore WordPress.DB

		$this->assertSame( '198.51.100.4', $row['ip'] );
		$this->assertSame( 'DE', $row['country'] );
		$this->assertSame( 'SQL injection', $row['reason'], 'control characters are stripped' );
		$this->assertEqualsWithDelta( time(), strtotime( $row['created_at'] . ' UTC' ), 5 );
	}

	public function test_record_defaults_the_action_and_truncates_long_values(): void {
		global $wpdb;
		$id  = $this->log->record( array( 'ip' => '198.51.100.4', 'rule' => str_repeat( 'r', 100 ), 'uri' => '/' . str_repeat( 'a', 3000 ) ) );
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->log->table()} WHERE id = %d", $id ), ARRAY_A ); // phpcs:ignore WordPress.DB

		$this->assertSame( BlockLogInterface::ACTION_BLOCKED, $row['action'] );
		$this->assertSame( 32, strlen( $row['rule'] ) );
		$this->assertSame( 2048, strlen( $row['uri'] ) );
	}

	public function test_record_keeps_multibyte_text_intact(): void {
		global $wpdb;
		$id  = $this->log->record( array( 'ip' => '198.51.100.4', 'reason' => 'Zugriff verweigert für Köln ✓ 日本' ) );
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT reason FROM {$this->log->table()} WHERE id = %d", $id ), ARRAY_A ); // phpcs:ignore WordPress.DB

		$this->assertSame( 'Zugriff verweigert für Köln ✓ 日本', $row['reason'] );
	}

	public function test_query_returns_newest_first_and_can_reverse(): void {
		$old = $this->seed( array( 'ip' => '198.51.100.1' ), 300 );
		$mid = $this->seed( array( 'ip' => '198.51.100.2' ), 200 );
		$new = $this->seed( array( 'ip' => '198.51.100.3' ), 100 );

		$desc = array_map( 'intval', array_column( $this->log->query(), 'id' ) );
		$asc  = array_map( 'intval', array_column( $this->log->query( array(), 50, 1, 'created_at', 'ASC' ), 'id' ) );

		$this->assertSame( array( $new, $mid, $old ), $desc );
		$this->assertSame( array( $old, $mid, $new ), $asc );
	}

	public function test_query_breaks_ties_by_id(): void {
		$a = $this->log->record( array( 'ip' => '198.51.100.1' ) );
		$b = $this->log->record( array( 'ip' => '198.51.100.2' ) );
		global $wpdb;
		$wpdb->query( "UPDATE {$this->log->table()} SET created_at = '2026-01-01 00:00:00'" ); // phpcs:ignore WordPress.DB

		$ids = array_map( 'intval', array_column( $this->log->query(), 'id' ) );

		$this->assertSame( array( $b, $a ), $ids );
	}

	public function test_query_filters_by_rule_action_and_country(): void {
		$this->seed( array( 'ip' => '198.51.100.1', 'rule' => 'waf', 'action' => 'blocked', 'country' => 'US' ) );
		$this->seed( array( 'ip' => '198.51.100.2', 'rule' => 'waf', 'action' => 'monitored', 'country' => 'DE' ) );
		$this->seed( array( 'ip' => '198.51.100.3', 'rule' => 'xmlrpc', 'action' => 'blocked', 'country' => 'DE' ) );

		$this->assertSame( 2, $this->log->count( array( 'rule' => 'waf' ) ) );
		$this->assertSame( 2, $this->log->count( array( 'action' => 'blocked' ) ) );
		$this->assertSame( 2, $this->log->count( array( 'country' => 'DE' ) ) );
		$this->assertSame( 1, $this->log->count( array( 'rule' => 'waf', 'action' => 'blocked', 'country' => 'US' ) ) );
		$this->assertSame( 0, $this->log->count( array( 'rule' => 'nope' ) ) );
		$this->assertCount( 1, $this->log->query( array( 'rule' => 'xmlrpc' ) ) );
	}

	public function test_query_filters_by_since(): void {
		$this->seed( array( 'ip' => '198.51.100.1' ), 7200 );
		$this->seed( array( 'ip' => '198.51.100.2' ), 60 );

		$since = gmdate( 'Y-m-d H:i:s', time() - 3600 );

		$this->assertSame( 1, $this->log->count( array( 'since' => $since ) ) );
		$this->assertSame( '198.51.100.2', $this->log->query( array( 'since' => $since ) )[0]['ip'] );
	}

	public function test_search_matches_ip_uri_reason_and_user_agent(): void {
		$this->seed( array( 'ip' => '198.51.100.1', 'uri' => '/wp-login.php' ) );
		$this->seed( array( 'ip' => '198.51.100.2', 'reason' => 'bad bot' ) );
		$this->seed( array( 'ip' => '198.51.100.3', 'user_agent' => 'sqlmap/1.0' ) );

		$this->assertSame( 1, $this->log->count( array( 'search' => 'wp-login' ) ) );
		$this->assertSame( 1, $this->log->count( array( 'search' => 'bad bot' ) ) );
		$this->assertSame( 1, $this->log->count( array( 'search' => 'sqlmap' ) ) );
		$this->assertSame( 1, $this->log->count( array( 'search' => '198.51.100.3' ) ) );
		$this->assertSame( 3, $this->log->count( array( 'search' => '198.51.100.' ) ) );
	}

	public function test_search_treats_like_wildcards_literally(): void {
		$this->seed( array( 'ip' => '198.51.100.1', 'uri' => '/a_b' ) );
		$this->seed( array( 'ip' => '198.51.100.2', 'uri' => '/axb' ) );
		$this->seed( array( 'ip' => '198.51.100.3', 'uri' => '/100%' ) );

		$this->assertSame( 1, $this->log->count( array( 'search' => 'a_b' ) ), '_ is not a wildcard' );
		$this->assertSame( 1, $this->log->count( array( 'search' => '100%' ) ) );
		$this->assertSame( 1, $this->log->count( array( 'search' => '%' ) ), '% only matches a literal percent sign' );
	}

	public function test_search_is_safe_against_quote_injection(): void {
		$this->seed( array( 'ip' => '198.51.100.1' ) );

		$this->assertSame( 0, $this->log->count( array( 'search' => "' OR '1'='1" ) ) );
		$this->assertSame( 0, $this->log->count( array( 'rule' => "x' OR 1=1 -- " ) ) );
		$this->assertSame( 1, $this->log->count(), 'table untouched' );
	}

	public function test_query_paginates(): void {
		for ( $i = 1; $i <= 5; $i++ ) {
			$this->seed( array( 'ip' => "198.51.100.{$i}" ), 100 - $i );
		}

		$page1 = $this->log->query( array(), 2, 1 );
		$page2 = $this->log->query( array(), 2, 2 );
		$page3 = $this->log->query( array(), 2, 3 );
		$page4 = $this->log->query( array(), 2, 4 );

		$this->assertCount( 2, $page1 );
		$this->assertCount( 2, $page2 );
		$this->assertCount( 1, $page3 );
		$this->assertSame( array(), $page4 );
		$this->assertSame( 5, $this->log->count() );
		$this->assertSame( '198.51.100.5', $page1[0]['ip'] );
		$this->assertSame( '198.51.100.1', $page3[0]['ip'] );
	}

	public function test_query_clamps_page_numbers_and_sizes(): void {
		$this->seed( array( 'ip' => '198.51.100.1' ) );

		$this->assertCount( 1, $this->log->query( array(), 0, 0 ), 'per_page < 1 becomes 1, page < 1 becomes 1' );
		$this->assertCount( 1, $this->log->query( array(), 5000, -3 ) );
	}

	public function test_query_ignores_unknown_sort_column(): void {
		$this->seed( array( 'ip' => '198.51.100.1' ) );

		$rows = $this->log->query( array(), 50, 1, 'id; DROP TABLE x', 'sideways' );

		$this->assertCount( 1, $rows );
		$this->assertSame( '', $GLOBALS['wpdb']->last_error );
	}

	public function test_query_can_sort_by_ip(): void {
		$this->seed( array( 'ip' => '198.51.100.9' ) );
		$this->seed( array( 'ip' => '198.51.100.1' ) );

		$rows = $this->log->query( array(), 50, 1, 'ip', 'ASC' );

		$this->assertSame( '198.51.100.1', $rows[0]['ip'] );
	}

	public function test_count_with_no_filters_and_empty_table(): void {
		$this->assertSame( 0, $this->log->count() );
		$this->assertSame( array(), $this->log->query() );
	}

	public function test_top_groups_and_orders_by_count_and_excludes_alerts(): void {
		$since = gmdate( 'Y-m-d H:i:s', time() - 3600 );
		foreach ( array( 'waf', 'waf', 'waf', 'xmlrpc', 'xmlrpc', 'user_agent' ) as $rule ) {
			$this->seed( array( 'ip' => '198.51.100.1', 'rule' => $rule ) );
		}
		$this->seed( array( 'ip' => '198.51.100.1', 'rule' => 'alerts', 'action' => BlockLogInterface::ACTION_ALERT ) );
		$this->seed( array( 'ip' => '198.51.100.1', 'rule' => 'waf' ), 7200 );

		$top = $this->log->top( 'rule', $since );

		$this->assertSame( array( 'waf' => 3, 'xmlrpc' => 2, 'user_agent' => 1 ), $top );
		$this->assertSame( array( 'waf', 'xmlrpc', 'user_agent' ), array_keys( $top ) );
	}

	public function test_top_respects_limit_and_skips_empty_values(): void {
		$since = gmdate( 'Y-m-d H:i:s', time() - 3600 );
		$this->seed( array( 'ip' => '198.51.100.1', 'country' => 'US' ) );
		$this->seed( array( 'ip' => '198.51.100.2', 'country' => 'US' ) );
		$this->seed( array( 'ip' => '198.51.100.3', 'country' => 'DE' ) );
		$this->seed( array( 'ip' => '198.51.100.4', 'country' => '' ) );

		$this->assertSame( array( 'US' => 2, 'DE' => 1 ), $this->log->top( 'country', $since ) );
		$this->assertSame( array( 'US' => 2 ), $this->log->top( 'country', $since, 1 ) );
	}

	public function test_top_by_ip_and_action(): void {
		$since = gmdate( 'Y-m-d H:i:s', time() - 3600 );
		$this->seed( array( 'ip' => '198.51.100.1', 'action' => 'blocked' ) );
		$this->seed( array( 'ip' => '198.51.100.1', 'action' => 'lockout' ) );
		$this->seed( array( 'ip' => '198.51.100.2', 'action' => 'blocked' ) );

		$this->assertSame( array( '198.51.100.1' => 2, '198.51.100.2' => 1 ), $this->log->top( 'ip', $since ) );
		$this->assertSame( array( 'blocked' => 2, 'lockout' => 1 ), $this->log->top( 'action', $since ) );
	}

	public function test_top_rejects_unknown_columns(): void {
		$this->seed( array( 'ip' => '198.51.100.1' ) );

		$this->assertSame( array(), $this->log->top( 'uri', '2000-01-01 00:00:00' ) );
		$this->assertSame( array(), $this->log->top( 'rule; DROP TABLE x', '2000-01-01 00:00:00' ) );
	}

	public function test_per_day_fills_missing_days_and_excludes_alerts(): void {
		$day = DAY_IN_SECONDS;
		$this->seed( array( 'ip' => '198.51.100.1' ) );
		$this->seed( array( 'ip' => '198.51.100.1' ) );
		$this->seed( array( 'ip' => '198.51.100.1' ), 2 * $day );
		$this->seed( array( 'ip' => '198.51.100.1', 'rule' => 'alerts', 'action' => BlockLogInterface::ACTION_ALERT ) );
		$this->seed( array( 'ip' => '198.51.100.1' ), 10 * $day );

		$series = $this->log->per_day( 4 );

		$this->assertCount( 4, $series );
		$this->assertSame( gmdate( 'Y-m-d', time() - 3 * $day ), array_key_first( $series ), 'oldest first' );
		$this->assertSame( gmdate( 'Y-m-d' ), array_key_last( $series ) );
		$this->assertSame( 2, $series[ gmdate( 'Y-m-d' ) ], 'alert not counted' );
		$this->assertSame( 1, $series[ gmdate( 'Y-m-d', time() - 2 * $day ) ] );
		$this->assertSame( 0, $series[ gmdate( 'Y-m-d', time() - 1 * $day ) ], 'missing day is zero' );
		$this->assertSame( 3, array_sum( $series ), 'row outside the window is not counted' );
	}

	public function test_per_day_clamps_the_range(): void {
		$this->assertCount( 1, $this->log->per_day( 0 ) );
		$this->assertCount( 365, $this->log->per_day( 9999 ) );
	}

	public function test_purge_older_than_deletes_only_old_rows(): void {
		$this->seed( array( 'ip' => '198.51.100.1' ), 40 * DAY_IN_SECONDS );
		$this->seed( array( 'ip' => '198.51.100.2' ), 31 * DAY_IN_SECONDS );
		$keep = $this->seed( array( 'ip' => '198.51.100.3' ), 29 * DAY_IN_SECONDS );
		$new  = $this->seed( array( 'ip' => '198.51.100.4' ) );

		$deleted = $this->log->purge_older_than( 30 );

		$this->assertSame( 2, $deleted );
		$left = array_map( 'intval', array_column( $this->log->query( array(), 50, 1, 'created_at', 'ASC' ), 'id' ) );
		$this->assertSame( array( $keep, $new ), $left );
	}

	public function test_purge_older_than_never_goes_below_one_day(): void {
		$this->seed( array( 'ip' => '198.51.100.1' ), 3600 );

		$this->assertSame( 0, $this->log->purge_older_than( 0 ) );
		$this->assertSame( 1, $this->log->count() );
	}

	public function test_clear_removes_everything(): void {
		// Runs first in its own transaction: TRUNCATE commits implicitly.
		$this->seed( array( 'ip' => '198.51.100.1' ) );
		$this->seed( array( 'ip' => '198.51.100.2' ) );

		$this->log->clear();

		$this->assertSame( 0, $this->log->count() );
	}

	public function test_ids_are_not_reused_after_a_delete(): void {
		$first = $this->seed( array( 'ip' => '198.51.100.1' ) );
		global $wpdb;
		$wpdb->delete( $this->log->table(), array( 'id' => $first ) );

		$second = $this->seed( array( 'ip' => '198.51.100.2' ) );

		$this->assertGreaterThan( $first, $second );
	}
}
