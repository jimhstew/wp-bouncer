<?php
/**
 * TrafficLog SQL against a real database.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Traffic;

use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Traffic\TrafficLog;

/**
 * @covers \WPBouncer\Traffic\TrafficLog
 */
final class TrafficLogTest extends IntegrationTestCase {

	/** @var TrafficLog */
	private $log;

	public function set_up() {
		parent::set_up();
		global $wpdb;
		$this->log = new TrafficLog( $wpdb );
	}

	/**
	 * @param array<string, mixed> $data        Row data for TrafficLog::record().
	 * @param int                  $seconds_ago Age.
	 */
	private function seed( array $data, int $seconds_ago = 0 ): int {
		global $wpdb;
		$data += array( 'ip' => '198.51.100.1', 'method' => 'GET', 'uri' => '/', 'status' => 200 );
		$id    = $this->log->record( $data );
		$this->assertGreaterThan( 0, $id );
		if ( $seconds_ago ) {
			$wpdb->update( $this->log->table(), array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - $seconds_ago ) ), array( 'id' => $id ) );
		}
		return $id;
	}

	public function test_record_stores_all_columns_and_classifies_the_client(): void {
		global $wpdb;
		$id = $this->log->record(
			array(
				'ip'         => '203.0.113.5',
				'method'     => 'get',
				'uri'        => '/hello?x=1',
				'status'     => 404,
				'referrer'   => 'https://example.com/a',
				'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
				'user_id'    => 7,
			)
		);
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->log->table()} WHERE id = %d", $id ), ARRAY_A ); // phpcs:ignore WordPress.DB

		$this->assertSame( '203.0.113.5', $row['ip'] );
		$this->assertSame( 'GET', $row['method'] );
		$this->assertSame( '/hello?x=1', $row['uri'] );
		$this->assertSame( '404', $row['status'] );
		$this->assertSame( 'https://example.com/a', $row['referrer'] );
		$this->assertSame( '7', $row['user_id'] );
		$this->assertSame( 'search_engine', $row['client'] );
		$this->assertEqualsWithDelta( time(), strtotime( $row['created_at'] . ' UTC' ), 5 );
	}

	public function test_record_removes_secret_query_values_before_storing(): void {
		global $wpdb;
		$id  = $this->log->record( array( 'ip' => '203.0.113.5', 'uri' => '/wp-login.php?action=rp&key=abc123&login=bob', 'referrer' => 'https://x.test/?token=zzz' ) );
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT uri, referrer FROM {$this->log->table()} WHERE id = %d", $id ), ARRAY_A ); // phpcs:ignore WordPress.DB

		$this->assertStringNotContainsString( 'abc123', $row['uri'] );
		$this->assertStringContainsString( 'key=[removed]', $row['uri'] );
		$this->assertStringContainsString( 'login=bob', $row['uri'] );
		$this->assertStringNotContainsString( 'zzz', $row['referrer'] );
	}

	public function test_record_with_out_of_range_status_stores_zero(): void {
		global $wpdb;
		$id = $this->log->record( array( 'ip' => '203.0.113.5', 'status' => 9999 ) );

		$this->assertSame( '0', $wpdb->get_var( "SELECT status FROM {$this->log->table()} WHERE id = {$id}" ) ); // phpcs:ignore WordPress.DB
	}

	public function test_record_returns_zero_and_prints_nothing_when_the_table_is_missing(): void {
		global $wpdb;
		$this->use_real_ddl();
		$wpdb->query( "DROP TABLE {$wpdb->prefix}bouncer_traffic" ); // phpcs:ignore WordPress.DB

		ob_start();
		$id  = $this->log->record( array( 'ip' => '203.0.113.5' ) );
		$out = ob_get_clean();

		$this->assertSame( 0, $id );
		$this->assertSame( '', $out, 'a missing table must not print errors into a page' );
	}

	public function test_query_orders_newest_first_and_filters_by_client(): void {
		$old = $this->seed( array( 'user_agent' => 'curl/8.0' ), 500 );
		$new = $this->seed( array( 'user_agent' => 'Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537' ), 100 );

		$all  = array_map( 'intval', array_column( $this->log->query(), 'id' ) );
		$tool = $this->log->query( array( 'client' => 'tool' ) );

		$this->assertSame( array( $new, $old ), $all );
		$this->assertCount( 1, $tool );
		$this->assertSame( (string) $old, $tool[0]['id'] );
		$this->assertSame( 1, $this->log->count( array( 'client' => 'browser' ) ) );
	}

	public function test_status_class_filter_uses_ranges(): void {
		foreach ( array( 200, 204, 301, 404, 403, 500 ) as $status ) {
			$this->seed( array( 'status' => $status ) );
		}

		$this->assertSame( 2, $this->log->count( array( 'status' => '2xx' ) ) );
		$this->assertSame( 1, $this->log->count( array( 'status' => '3xx' ) ) );
		$this->assertSame( 2, $this->log->count( array( 'status' => '4xx' ) ) );
		$this->assertSame( 1, $this->log->count( array( 'status' => '5xx' ) ) );
		$this->assertSame( 6, $this->log->count( array( 'status' => 'bogus' ) ), 'an unknown class filters nothing' );
	}

	public function test_filters_by_ip_since_and_search(): void {
		$this->seed( array( 'ip' => '198.51.100.1', 'uri' => '/shop?item=5' ), 7200 );
		$this->seed( array( 'ip' => '198.51.100.2', 'uri' => '/blog', 'referrer' => 'https://search.example/q' ) );
		$this->seed( array( 'ip' => '198.51.100.2', 'uri' => '/about', 'user_agent' => 'Foo/1' ) );

		$this->assertSame( 2, $this->log->count( array( 'ip' => '198.51.100.2' ) ) );
		$this->assertSame( 2, $this->log->count( array( 'since' => gmdate( 'Y-m-d H:i:s', time() - 3600 ) ) ) );
		$this->assertSame( 1, $this->log->count( array( 'search' => 'shop' ) ) );
		$this->assertSame( 1, $this->log->count( array( 'search' => 'search.example' ) ), 'referrer is searched' );
		$this->assertSame( 1, $this->log->count( array( 'search' => 'Foo/1' ) ), 'user agent is searched' );
		$this->assertSame( 1, $this->log->count( array( 'ip' => '198.51.100.2', 'search' => 'blog', 'status' => '2xx' ) ) );
	}

	public function test_search_escapes_like_wildcards_and_quotes(): void {
		$this->seed( array( 'uri' => '/a_b' ) );
		$this->seed( array( 'uri' => '/axb' ) );

		$this->assertSame( 1, $this->log->count( array( 'search' => 'a_b' ) ) );
		$this->assertSame( 0, $this->log->count( array( 'search' => "'; DROP TABLE x; --" ) ) );
		$this->assertSame( 2, $this->log->count() );
	}

	public function test_query_paginates_and_sorts_by_allowed_columns_only(): void {
		for ( $i = 1; $i <= 5; $i++ ) {
			$this->seed( array( 'ip' => "198.51.100.{$i}" ), 100 - $i );
		}

		$this->assertCount( 2, $this->log->query( array(), 2, 1 ) );
		$this->assertCount( 1, $this->log->query( array(), 2, 3 ) );
		$this->assertSame( array(), $this->log->query( array(), 2, 9 ) );
		$this->assertSame( '198.51.100.1', $this->log->query( array(), 50, 1, 'ip', 'ASC' )[0]['ip'] );
		$this->assertCount( 5, $this->log->query( array(), 50, 1, 'user_agent; DROP', 'ASC' ) );
		$this->assertSame( '', $GLOBALS['wpdb']->last_error );
	}

	public function test_unique_ips_counts_distinct_addresses_since(): void {
		$this->seed( array( 'ip' => '198.51.100.1' ) );
		$this->seed( array( 'ip' => '198.51.100.1' ) );
		$this->seed( array( 'ip' => '198.51.100.2' ) );
		$this->seed( array( 'ip' => '198.51.100.3' ), 7200 );

		$this->assertSame( 2, $this->log->unique_ips( gmdate( 'Y-m-d H:i:s', time() - 3600 ) ) );
		$this->assertSame( 3, $this->log->unique_ips( gmdate( 'Y-m-d H:i:s', time() - 86400 ) ) );
		$this->assertSame( 0, $this->log->unique_ips( gmdate( 'Y-m-d H:i:s', time() + 60 ) ) );
	}

	public function test_by_client_groups_largest_first(): void {
		$this->seed( array( 'user_agent' => 'curl/8.0' ) );
		$this->seed( array( 'user_agent' => 'curl/7.0' ) );
		$this->seed( array( 'user_agent' => 'curl/7.1' ) );
		$this->seed( array( 'user_agent' => 'Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537' ) );
		$this->seed( array( 'user_agent' => 'curl/old' ), 7200 );

		$by = $this->log->by_client( gmdate( 'Y-m-d H:i:s', time() - 3600 ) );

		$this->assertSame( array( 'tool' => 3, 'browser' => 1 ), $by );
		$this->assertSame( 'tool', array_key_first( $by ) );
	}

	public function test_purge_older_than_respects_retention_and_the_seven_day_cap(): void {
		$this->seed( array( 'ip' => '198.51.100.1' ), 9 * DAY_IN_SECONDS );
		$this->seed( array( 'ip' => '198.51.100.2' ), 3 * DAY_IN_SECONDS );
		$this->seed( array( 'ip' => '198.51.100.3' ), 3600 );

		$this->assertSame( 1, $this->log->purge_older_than( 30 ), 'a retention above 7 days is capped at 7' );
		$this->assertSame( 2, $this->log->count() );
		$this->assertSame( 1, $this->log->purge_older_than( 2 ) );
		$this->assertSame( 1, $this->log->count() );
		$this->assertSame( 0, $this->log->purge_older_than( 0 ), 'less than one day is treated as one day' );
		$this->assertSame( 1, $this->log->count() );
	}

	public function test_clear_removes_every_row(): void {
		$this->seed( array( 'ip' => '198.51.100.1' ) );
		$this->seed( array( 'ip' => '198.51.100.2' ) );

		$this->log->clear();

		$this->assertSame( 0, $this->log->count() );
	}
}
