<?php
/**
 * TrafficRecorder with the real request, user and database.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Traffic;

use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Traffic\TrafficLog;
use WPBouncer\Traffic\TrafficRecorder;

/**
 * @covers \WPBouncer\Traffic\TrafficRecorder
 */
final class TrafficRecorderTest extends IntegrationTestCase {

	private function enable( array $traffic = array() ): TrafficRecorder {
		$this->set_settings( array( 'traffic' => array_merge( array( 'enabled' => true ), $traffic ) ) );
		return new TrafficRecorder( $this->plugin );
	}

	/** @return array<int, array<string, string>> */
	private function rows(): array {
		global $wpdb;
		return (array) ( new TrafficLog( $wpdb ) )->query( array(), 100, 1, 'created_at', 'ASC' );
	}

	public function test_register_always_hooks_the_purge_but_records_only_when_enabled(): void {
		$off = new TrafficRecorder( $this->plugin );
		$off->register();
		$this->assertNotFalse( has_action( TrafficRecorder::PURGE_HOOK, array( $off, 'purge' ) ) );
		$this->assertFalse( has_action( 'shutdown', array( $off, 'record' ) ), 'disabled by default' );

		$on = $this->enable();
		$on->register();
		$this->assertSame( 100, has_action( 'shutdown', array( $on, 'record' ) ), 'late, after alert mail' );
	}

	public function test_it_records_a_request_with_its_details(): void {
		$this->fake_request(
			array(
				'REMOTE_ADDR'     => '198.51.100.20',
				'REQUEST_METHOD'  => 'GET',
				'REQUEST_URI'     => '/blog/hello/?utm=1',
				'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537',
				'HTTP_REFERER'    => 'https://news.example/story',
			)
		);
		$recorder = $this->enable();

		$recorder->record();

		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( '198.51.100.20', $rows[0]['ip'] );
		$this->assertSame( 'GET', $rows[0]['method'] );
		$this->assertSame( '/blog/hello/?utm=1', $rows[0]['uri'] );
		$this->assertSame( 'https://news.example/story', $rows[0]['referrer'] );
		$this->assertSame( 'browser', $rows[0]['client'] );
		$this->assertSame( '0', $rows[0]['user_id'] );
	}

	public function test_it_records_the_logged_in_user(): void {
		$id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		wp_set_current_user( $id );
		$this->fake_request();
		$recorder = $this->enable();

		$recorder->record();

		$this->assertSame( (string) $id, $this->rows()[0]['user_id'] );
	}

	public function test_it_removes_secret_query_values_from_the_uri_and_referrer(): void {
		$this->fake_request(
			array(
				'REQUEST_URI'  => '/wp-login.php?action=rp&key=SECRETKEY&login=bob&access_token=TOK123',
				'HTTP_REFERER' => 'https://x.example/?password=hunter2&ok=1',
			)
		);
		$recorder = $this->enable();

		$recorder->record();

		$row = $this->rows()[0];
		foreach ( array( 'SECRETKEY', 'TOK123' ) as $secret ) {
			$this->assertStringNotContainsString( $secret, $row['uri'] );
		}
		$this->assertStringNotContainsString( 'hunter2', $row['referrer'] );
		$this->assertStringContainsString( 'login=bob', $row['uri'] );
		$this->assertStringContainsString( 'ok=1', $row['referrer'] );
	}

	public function test_it_skips_cron_and_heartbeat_by_default(): void {
		$recorder = $this->enable();

		$this->fake_request( array( 'REQUEST_URI' => '/wp-cron.php?doing_wp_cron=123' ) );
		$recorder->record();
		$this->fake_request( array( 'REQUEST_URI' => '/wp-admin/admin-ajax.php', 'REQUEST_METHOD' => 'POST' ), array(), array( 'action' => 'heartbeat' ) );
		$recorder->record();

		$this->assertCount( 0, $this->rows() );
	}

	public function test_other_ajax_calls_and_normal_pages_are_still_recorded(): void {
		$recorder = $this->enable();

		$this->fake_request( array( 'REQUEST_URI' => '/wp-admin/admin-ajax.php', 'REQUEST_METHOD' => 'POST' ), array(), array( 'action' => 'my_action' ) );
		$recorder->record();
		$this->fake_request( array( 'REQUEST_URI' => '/about/' ) );
		$recorder->record();

		$this->assertCount( 2, $this->rows() );
	}

	public function test_background_requests_are_recorded_when_asked_for(): void {
		$recorder = $this->enable( array( 'skip_background' => false ) );
		$this->fake_request( array( 'REQUEST_URI' => '/wp-cron.php' ) );

		$recorder->record();

		$this->assertCount( 1, $this->rows() );
	}

	public function test_it_skips_administrators_when_asked_but_not_other_users(): void {
		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$sub   = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$recorder = $this->enable( array( 'skip_admins' => true ) );

		wp_set_current_user( $admin );
		$this->fake_request();
		$recorder->record();
		$this->assertCount( 0, $this->rows(), 'administrator skipped' );

		wp_set_current_user( $sub );
		$this->fake_request();
		$recorder->record();
		$this->assertCount( 1, $this->rows(), 'a subscriber is recorded' );
	}

	public function test_administrators_are_recorded_by_default(): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$this->fake_request();
		$recorder = $this->enable();

		$recorder->record();

		$this->assertCount( 1, $this->rows() );
	}

	public function test_it_never_breaks_the_page_when_the_table_is_missing(): void {
		global $wpdb;
		$this->use_real_ddl();
		$wpdb->query( "DROP TABLE {$wpdb->prefix}bouncer_traffic" ); // phpcs:ignore WordPress.DB
		$this->fake_request();
		$recorder = $this->enable();

		ob_start();
		$recorder->record();
		$out = ob_get_clean();

		$this->assertSame( '', $out );
	}

	public function test_the_status_column_is_a_valid_http_code_or_zero(): void {
		// Under the CLI http_response_code() is false, which the recorder stores as 0 (unknown).
		$this->fake_request();
		$recorder = $this->enable();

		$recorder->record();

		$status = (int) $this->rows()[0]['status'];
		$this->assertTrue( 0 === $status || ( $status >= 100 && $status <= 599 ) );
	}

	public function test_is_background_detects_cron_and_heartbeat_only(): void {
		$this->assertTrue( TrafficRecorder::is_background( '/wp-cron.php', array() ) );
		$this->assertTrue( TrafficRecorder::is_background( '/wp-admin/admin-ajax.php', array( 'action' => 'heartbeat' ) ) );
		$this->assertFalse( TrafficRecorder::is_background( '/wp-admin/admin-ajax.php', array( 'action' => 'save' ) ) );
		$this->assertFalse( TrafficRecorder::is_background( '/wp-admin/admin-ajax.php', array() ) );
		$this->assertFalse( TrafficRecorder::is_background( '/', array( 'action' => 'heartbeat' ) ) );
	}

	public function test_purge_uses_the_configured_retention(): void {
		global $wpdb;
		$log      = new TrafficLog( $wpdb );
		$recorder = $this->enable( array( 'retention_days' => 2 ) );
		$old      = $log->record( array( 'ip' => '198.51.100.1' ) );
		$new      = $log->record( array( 'ip' => '198.51.100.2' ) );
		$wpdb->update( $log->table(), array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 3 * DAY_IN_SECONDS ) ), array( 'id' => $old ) );

		$recorder->purge();

		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( (string) $new, $rows[0]['id'] );
	}

	public function test_purge_never_keeps_more_than_a_week(): void {
		global $wpdb;
		$log      = new TrafficLog( $wpdb );
		$recorder = $this->enable();
		$old      = $log->record( array( 'ip' => '198.51.100.1' ) );
		$wpdb->update( $log->table(), array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 8 * DAY_IN_SECONDS ) ), array( 'id' => $old ) );

		$recorder->purge();

		$this->assertCount( 0, $this->rows() );
	}

	public function test_the_purge_cron_hook_runs_the_purge(): void {
		global $wpdb;
		$log = new TrafficLog( $wpdb );
		$old = $log->record( array( 'ip' => '198.51.100.1' ) );
		$wpdb->update( $log->table(), array( 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 9 * DAY_IN_SECONDS ) ), array( 'id' => $old ) );
		$this->assertNotFalse( has_action( TrafficRecorder::PURGE_HOOK ), 'the booted plugin listens for the purge job' );

		do_action( TrafficRecorder::PURGE_HOOK );

		$this->assertCount( 0, $this->rows() );
	}
}
