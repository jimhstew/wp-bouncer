<?php
/**
 * RedactionMigration against the real database.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Storage;

use WPBouncer\Installer;
use WPBouncer\Storage\RedactionMigration;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Storage\RedactionMigration
 */
final class RedactionMigrationTest extends IntegrationTestCase {

	private string $log;

	public function set_up() {
		parent::set_up();
		global $wpdb;
		$this->log = $wpdb->prefix . 'bouncer_log';
		delete_option( RedactionMigration::STATE_OPTION );
		delete_option( RedactionMigration::LOCK_OPTION );
		wp_clear_scheduled_hook( RedactionMigration::HOOK );
	}

	private function insert_reason( string $reason ): int {
		global $wpdb;
		$wpdb->insert(
			$this->log,
			array(
				'created_at' => '2026-01-01 00:00:00',
				'ip'         => '198.51.100.7',
				'rule'       => 'login_lockout',
				'reason'     => $reason,
			)
		);
		return (int) $wpdb->insert_id;
	}

	private function reason_of( int $id ): string {
		global $wpdb;
		return (string) $wpdb->get_var( $wpdb->prepare( 'SELECT reason FROM %i WHERE id = %d', $this->log, $id ) );
	}

	private function lookup( array $known ): RedactionMigration {
		return new RedactionMigration( static fn ( string $n ): ?string => in_array( $n, $known, true ) ? $n : null );
	}

	public function test_an_existing_username_is_kept_and_an_unknown_one_removed(): void {
		$keep = $this->insert_reason( '5 failed logins (last username "alice") – locked out for 60 min' );
		$drop = $this->insert_reason( '5 failed logins (last username "hunter2") – locked out for 60 min' );
		RedactionMigration::begin();
		$this->assertTrue( $this->lookup( array( 'alice' ) )->run( 5.0 ) );
		$this->assertStringContainsString( '"alice"', $this->reason_of( $keep ) );
		$this->assertSame( '5 failed logins (last: unknown username) – locked out for 60 min', $this->reason_of( $drop ) );
	}

	public function test_a_password_containing_quotes_and_brackets_is_removed_whole(): void {
		$id = $this->insert_reason( '5 failed logins (last username "pa") ss"w)o(rd") – locked out for 60 min' );
		RedactionMigration::begin();
		$this->lookup( array() )->run( 5.0 );
		$this->assertSame( '5 failed logins (last: unknown username) – locked out for 60 min', $this->reason_of( $id ) );
	}

	public function test_a_reason_cut_short_by_the_column_is_removed_to_its_end(): void {
		$id  = $this->insert_reason( '5 failed logins (last username "start-of-a-long-pass") and more' );
		$cut = $this->insert_reason( '5 failed logins (last username "pa") ss' );
		RedactionMigration::begin();
		$this->lookup( array() )->run( 5.0 );
		$this->assertSame( '5 failed logins (last: unknown username)', $this->reason_of( $cut ) );
		$this->assertStringNotContainsString( 'start-of', $this->reason_of( $id ) );
		$this->assertStringNotContainsString( 'ss', $this->reason_of( $cut ) );
	}

	public function test_it_resumes_from_a_saved_cursor(): void {
		global $wpdb;
		$ids = array();
		for ( $i = 0; $i < 4; $i++ ) {
			$wpdb->insert(
				$this->log,
				array(
					'created_at' => '2026-01-01 00:00:00',
					'rule'       => 'waf',
					'uri'        => "/p{$i}?token=S{$i}",
				)
			);
			$ids[] = (int) $wpdb->insert_id;
		}
		// Rows up to the second were handled by an earlier run; the cursor says so.
		update_option(
			RedactionMigration::STATE_OPTION,
			array(
				'log'     => $ids[1],
				'traffic' => 0,
				'reasons' => 0,
			),
			false
		);

		$this->assertTrue( $this->lookup( array() )->run( 5.0 ) );

		$uris = $wpdb->get_col( "SELECT uri FROM {$this->log} WHERE rule = 'waf' ORDER BY id" ); // phpcs:ignore WordPress.DB
		$this->assertSame( '/p0?token=S0', $uris[0], 'before the cursor: not revisited' );
		$this->assertSame( '/p1?token=S1', $uris[1] );
		$this->assertSame( '/p2?token=[removed]', $uris[2] );
		$this->assertSame( '/p3?token=[removed]', $uris[3] );
		$this->assertFalse( RedactionMigration::pending() );
	}

	public function test_a_fresh_lock_blocks_a_second_run_and_a_stale_one_is_taken_over(): void {
		$id = $this->insert_reason( '5 failed logins (last username "x") – locked out for 60 min' );
		RedactionMigration::begin();
		update_option( RedactionMigration::LOCK_OPTION, time() - 10, false );
		$this->assertFalse( $this->lookup( array() )->run( 5.0 ), 'someone else is running' );
		$this->assertStringContainsString( '"x"', $this->reason_of( $id ) );

		update_option( RedactionMigration::LOCK_OPTION, time() - 121, false );
		$this->assertTrue( $this->lookup( array() )->run( 5.0 ), 'a lock older than 120 s is abandoned' );
		$this->assertStringNotContainsString( '"x"', $this->reason_of( $id ) );
		$this->assertFalse( get_option( RedactionMigration::LOCK_OPTION ), 'lock released' );
	}

	public function test_daily_maintenance_reschedules_an_unscheduled_pending_migration(): void {
		RedactionMigration::begin();
		$this->assertFalse( wp_next_scheduled( RedactionMigration::HOOK ) );

		$this->plugin->daily_maintenance();

		$this->assertNotFalse( wp_next_scheduled( RedactionMigration::HOOK ) );
	}

	public function test_daily_maintenance_schedules_nothing_when_no_migration_is_pending(): void {
		$this->plugin->daily_maintenance();
		$this->assertFalse( wp_next_scheduled( RedactionMigration::HOOK ) );
	}

	public function test_an_administrators_admin_request_continues_the_migration_and_shows_a_notice(): void {
		global $wpdb;
		$wpdb->insert(
			$this->log,
			array(
				'created_at' => '2026-01-01 00:00:00',
				'rule'       => 'waf',
				'uri'        => '/a?token=S',
			)
		);
		RedactionMigration::begin();
		$notices = new \WPBouncer\Admin\DataNotices();

		wp_set_current_user( 0 );
		$notices->continue_migration();
		$this->assertTrue( RedactionMigration::pending(), 'visitors and non-admins do not run it' );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		ob_start();
		$notices->render();
		$this->assertStringContainsString( 'removing secrets', (string) ob_get_clean() );
		$notices->continue_migration();
		$this->assertFalse( RedactionMigration::pending() );
		ob_start();
		$notices->render();
		$this->assertSame( '', (string) ob_get_clean() );
		wp_set_current_user( 0 );
	}

	public function test_user_lookup_keeps_the_login_of_a_real_account(): void {
		$login = 'wpb_s10_keep';
		self::factory()->user->create( array( 'user_login' => $login ) );
		$id = $this->insert_reason( '5 failed logins (last username "' . $login . '") – locked out for 60 min' );
		RedactionMigration::begin();
		( new RedactionMigration( Installer::user_lookup() ) )->run( 5.0 );
		$this->assertStringContainsString( '"' . $login . '"', $this->reason_of( $id ) );
	}
}
