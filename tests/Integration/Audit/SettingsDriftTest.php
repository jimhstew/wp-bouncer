<?php
/**
 * WPB-12: settings changed while the plugin was not loaded are found.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Audit;

use WPBouncer\Admin\AdminController;
use WPBouncer\Audit\FingerprintStore;
use WPBouncer\Audit\SettingsAuditor;
use WPBouncer\Audit\SettingsDriftMonitor;
use WPBouncer\Log\BlockLog;
use WPBouncer\Settings;
use WPBouncer\Storage\OptionLock;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Audit\SettingsDriftMonitor
 * @covers \WPBouncer\Audit\FingerprintStore
 * @covers \WPBouncer\Storage\OptionLock
 */
final class SettingsDriftTest extends IntegrationTestCase {

	/** Set up: a baseline, a clean log and mailbox. */
	public function set_up() {
		parent::set_up();
		$this->fake_request();
		wp_set_current_user( 0 );
		delete_option( FingerprintStore::RECORD_OPTION );
		delete_option( FingerprintStore::MARKER_OPTION );
		delete_option( FingerprintStore::LOCK_OPTION );
		delete_transient( FingerprintStore::THROTTLE_TRANSIENT );
		update_option( Settings::OPTION, Settings::defaults() );
		$this->plugin->drift_monitor()->check( SettingsDriftMonitor::TRIGGER_CRON );
		$this->plugin->alerts()->flush();
		$this->clear_mail();
		$this->empty_log();
	}

	/** Delete log rows without DDL. */
	private function empty_log(): void {
		global $wpdb;
		$wpdb->query( "DELETE FROM {$wpdb->prefix}bouncer_log" ); // phpcs:ignore WordPress.DB
	}

	/** @return array<int, array<string, string>> */
	private function rows(): array {
		global $wpdb;
		return (array) ( new BlockLog( $wpdb ) )->query( array( 'rule' => AdminController::SETTINGS_LOG_RULE ) );
	}

	/**
	 * Change the settings option behind WordPress's back (SQL), as an edit made while the plugin was off.
	 *
	 * @param array<string, mixed> $over Overrides.
	 */
	private function sql_edit( array $over ): void {
		global $wpdb;
		$new = array_replace_recursive( Settings::defaults(), $over );
		$wpdb->update( $wpdb->options, array( 'option_value' => serialize( $new ) ), array( 'option_name' => Settings::OPTION ) ); // phpcs:ignore WordPress.DB, WordPress.PHP.DiscouragedPHPFunctions
		wp_cache_delete( 'alloptions', 'options' );
		wp_cache_delete( Settings::OPTION, 'options' );
	}

	private function check( string $trigger = SettingsDriftMonitor::TRIGGER_CRON ): void {
		$this->plugin->drift_monitor()->check( $trigger );
	}

	/** @return array<int, array<string, mixed>> */
	private function mails(): array {
		$this->plugin->alerts()->flush();
		return $this->sent_mail();
	}

	/** Hold the monitor's lock the way another request would. */
	private function hold_lock( int $age = 0 ): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", FingerprintStore::LOCK_OPTION, ( time() - $age ) . '|othertoken' ) ); // phpcs:ignore WordPress.DB
	}

	public function test_the_baseline_is_silent_and_sets_the_marker(): void {
		$this->assertNotFalse( get_option( FingerprintStore::RECORD_OPTION ) );
		$this->assertNotFalse( get_option( FingerprintStore::MARKER_OPTION ) );
		$this->assertCount( 0, $this->rows() );
	}

	public function test_a_sql_edit_gives_one_row_one_mail_and_a_new_baseline(): void {
		$this->sql_edit( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) );
		$this->check();

		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( 'alert', $rows[0]['action'] );
		$this->assertStringContainsString( 'rules.waf.enabled', $rows[0]['reason'] );
		$this->assertStringContainsString( 'actor unknown', $rows[0]['reason'] );
		foreach ( array( 'ip', 'country', 'user_agent', 'method', 'uri' ) as $column ) {
			$this->assertSame( '', (string) $rows[0][ $column ], $column );
		}
		$mail = $this->mails();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'outside WP Bouncer', $mail[0]['subject'] . $mail[0]['body'] );

		$this->check();
		$this->assertCount( 1, $this->rows(), 'the record was replaced: a second check finds nothing' );
		$this->assertFalse( get_option( Settings::OPTION )['rules']['waf']['enabled'], 'nothing is reverted' );
	}

	public function test_an_unaudited_update_option_is_found(): void {
		remove_all_actions( 'update_option_' . Settings::OPTION );
		update_option( Settings::OPTION, array_replace_recursive( Settings::defaults(), array( 'mode' => 'monitor' ) ) );
		$this->check();
		$this->assertCount( 1, $this->rows() );
	}

	public function test_an_unaudited_delete_names_the_whole_option(): void {
		remove_all_actions( 'delete_option_' . Settings::OPTION );
		delete_option( Settings::OPTION );
		$this->check();
		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'settings', $rows[0]['reason'] );
	}

	public function test_audited_writes_leave_no_drift_and_update_the_record(): void {
		update_option( Settings::OPTION, array_replace_recursive( Settings::defaults(), array( 'mode' => 'monitor' ) ) );
		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringStartsWith( 'Settings changed by', $rows[0]['reason'] );
		$this->check();
		$this->assertCount( 1, $this->rows() );
	}

	public function test_a_save_cannot_mask_an_earlier_sql_edit(): void {
		$this->sql_edit( array( 'allowlist' => array( '198.51.100.1' ) ) );
		update_option( Settings::OPTION, array_replace_recursive( Settings::defaults(), array( 'mode' => 'monitor' ) ) );

		$reasons = array_column( array_reverse( $this->rows() ), 'reason' ); // Oldest first.
		$this->assertCount( 2, $reasons );
		$this->assertStringContainsString( 'outside WP Bouncer', $reasons[0] );
		$this->assertStringContainsString( 'allowlist', $reasons[0] );
		$this->assertStringStartsWith( 'Settings changed by', $reasons[1] );
		$this->assertStringContainsString( 'mode', $reasons[1] );
	}

	public function test_writing_the_record_fires_no_audit_hook(): void {
		$count = 0;
		add_action(
			'wp_bouncer_settings_changed',
			static function () use ( &$count ): void {
				++$count;
			}
		);
		$this->sql_edit( array( 'mode' => 'monitor' ) );
		$this->check();
		$this->assertSame( 1, $count, 'one call for the drift, none for the record write' );
	}

	public function test_a_listener_that_saves_again_causes_no_false_drift(): void {
		$done = false;
		add_action(
			'wp_bouncer_settings_changed',
			static function () use ( &$done ): void {
				if ( ! $done ) {
					$done = true;
					update_option( Settings::OPTION, array_replace_recursive( Settings::defaults(), array( 'mode' => 'monitor' ) ) );
				}
			}
		);
		$this->sql_edit( array( 'allowlist' => array( '198.51.100.1' ) ) );
		$this->check();
		$before = count( $this->rows() );
		$this->check();
		$this->assertSame( $before, count( $this->rows() ) );
	}

	public function test_no_record_with_a_marker_is_reported_and_without_is_silent(): void {
		delete_option( FingerprintStore::RECORD_OPTION );
		$this->check();
		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'fingerprint missing', $rows[0]['reason'] );

		$this->empty_log();
		delete_option( FingerprintStore::RECORD_OPTION );
		delete_option( FingerprintStore::MARKER_OPTION );
		$this->check();
		$this->assertCount( 0, $this->rows(), 'documented residual: both deleted gives a silent baseline' );
	}

	public function test_a_changed_key_is_reported(): void {
		add_filter(
			'salt',
			static function ( $salt, $scheme ) {
				return 'auth' === $scheme ? 'a different salt' : $salt;
			},
			10,
			2
		);
		$this->check();
		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'Security keys changed', $rows[0]['reason'] );
	}

	public function test_the_row_is_written_even_when_alerts_are_off_and_no_mail_goes(): void {
		update_option( Settings::OPTION, array_replace_recursive( Settings::defaults(), array( 'alerts' => array( 'firewall_changes' => false ) ) ) );
		$this->plugin->alerts()->flush();
		$this->empty_log();
		$this->clear_mail();
		$this->sql_edit( array( 'alerts' => array( 'firewall_changes' => false ), 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) );
		$this->check();
		$this->assertCount( 1, $this->rows() );
		$this->assertCount( 0, $this->mails() );
	}

	public function test_silencing_alerts_forces_the_mail_to_the_site_admin(): void {
		$this->sql_edit( array( 'alerts' => array( 'enabled' => false, 'recipients' => array( 'attacker@example.org' ) ) ) );
		$this->check();
		$mail = $this->mails();
		$this->assertCount( 1, $mail );
		$to = wp_json_encode( $mail[0]['to'] );
		$this->assertStringContainsString( (string) get_option( 'admin_email' ), $to );
	}

	public function test_at_most_one_row_an_hour(): void {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->sql_edit( array( 'allowlist' => array( '198.51.100.' . ( $i + 1 ) ) ) );
			$this->check();
		}
		$this->assertCount( 1, $this->rows() );

		// An hour later the accumulated change is reported.
		global $wpdb;
		$record = \WPBouncer\Audit\FingerprintRecord::from_stored( get_option( FingerprintStore::RECORD_OPTION ) );
		$key    = new \WPBouncer\Audit\FingerprintKey( wp_salt( 'auth' ), get_current_blog_id() );
		( new FingerprintStore() )->save( $record->with_logged( $key, time() - 2 * HOUR_IN_SECONDS ) );
		$this->check();
		$this->assertCount( 2, $this->rows() );
	}

	public function test_a_held_lock_blocks_the_check_and_a_stale_one_is_taken_over(): void {
		$this->sql_edit( array( 'mode' => 'monitor' ) );
		$this->hold_lock();
		$this->check();
		$this->assertCount( 0, $this->rows() );

		$this->empty_log();
		global $wpdb;
		$wpdb->delete( $wpdb->options, array( 'option_name' => FingerprintStore::LOCK_OPTION ) ); // phpcs:ignore WordPress.DB
		$this->hold_lock( 120 );
		$this->check();
		$this->assertCount( 1, $this->rows() );
		$this->assertFalse( get_option( FingerprintStore::LOCK_OPTION ), 'released' );
	}

	public function test_a_stale_owner_cannot_release_the_new_owners_lock(): void {
		$lock  = new OptionLock( 'wp_bouncer_test_lock', 60 );
		$first = $lock->claim();
		$this->assertNotNull( $first );
		$this->assertNull( $lock->claim() );
		$lock->release( 'wrongtoken' );
		$this->assertNull( $lock->claim(), 'a wrong token does not release' );
		$lock->release( $first );
		$second = $lock->claim();
		$this->assertNotNull( $second );
		$lock->release( $first );
		$this->assertNull( $lock->claim(), 'the old token no longer releases the new lock' );
		$lock->release( $second );
	}

	public function test_a_save_goes_ahead_after_waiting_for_a_held_lock(): void {
		$this->hold_lock();
		$start = microtime( true );
		update_option( Settings::OPTION, array_replace_recursive( Settings::defaults(), array( 'mode' => 'monitor' ) ) );
		$this->assertGreaterThan( 1.5, microtime( true ) - $start );
		$this->assertCount( 1, $this->rows() );
		$this->check();
		$this->assertCount( 1, $this->rows(), 'the record describes the saved value' );
	}

	public function test_a_failed_record_write_still_gives_the_row_and_retries(): void {
		$this->sql_edit( array( 'mode' => 'monitor' ) );
		add_filter(
			'pre_update_option_' . FingerprintStore::RECORD_OPTION,
			static function ( $value, $old ) {
				return $old;
			},
			10,
			2
		);
		$this->check();
		$this->assertCount( 1, $this->rows() );
	}

	public function test_an_error_never_escapes_and_leaves_the_record(): void {
		$before = get_option( FingerprintStore::RECORD_OPTION );
		$this->sql_edit( array( 'mode' => 'monitor' ) );
		add_filter(
			'salt',
			static function () {
				throw new \RuntimeException( 'boom secret' );
			}
		);
		$this->check();
		$this->assertSame( $before, get_option( FingerprintStore::RECORD_OPTION ) );
		$this->assertCount( 0, $this->rows() );
	}

	public function test_the_options_are_not_autoloaded(): void {
		global $wpdb;
		foreach ( array( FingerprintStore::RECORD_OPTION, FingerprintStore::MARKER_OPTION ) as $name ) {
			$auto = $wpdb->get_var( $wpdb->prepare( "SELECT autoload FROM {$wpdb->options} WHERE option_name = %s", $name ) ); // phpcs:ignore WordPress.DB
			$this->assertNotContains( $auto, array( 'yes', 'on', 'auto', 'auto-on' ), $name );
			$this->assertArrayNotHasKey( $name, wp_load_alloptions( true ) );
		}
	}

	public function test_the_admin_check_is_for_managers_and_throttled(): void {
		$reads = 0;
		add_filter(
			'wp_bouncer_settings_drift_check',
			static function ( $run ) use ( &$reads ) {
				++$reads;
				return $run;
			}
		);
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		$this->plugin->drift_monitor()->on_admin_init();
		$this->assertSame( 0, $reads );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$this->plugin->drift_monitor()->on_admin_init();
		$this->plugin->drift_monitor()->on_admin_init();
		$this->assertSame( 1, $reads, 'two page loads, one compare' );
	}

	public function test_the_filter_can_skip_a_check_but_not_the_save_path(): void {
		add_filter( 'wp_bouncer_settings_drift_check', '__return_false' );
		$this->sql_edit( array( 'allowlist' => array( '198.51.100.1' ) ) );
		$this->check();
		$this->assertCount( 0, $this->rows() );
		update_option( Settings::OPTION, array_replace_recursive( Settings::defaults(), array( 'mode' => 'monitor' ) ) );
		$this->assertCount( 2, $this->rows() );
	}

	public function test_drift_rows_are_not_threats(): void {
		global $wpdb;
		$this->sql_edit( array( 'mode' => 'monitor' ) );
		$this->check();
		$this->assertSame( array(), ( new BlockLog( $wpdb ) )->threats_by_country( array(), '2000-01-01 00:00:00', '2100-01-01 00:00:00' ) );
	}

	public function test_the_hooks_fire_with_paths_and_the_kind(): void {
		$calls = array();
		add_action(
			'wp_bouncer_settings_drift',
			static function ( ...$args ) use ( &$calls ): void {
				$calls[] = $args;
			},
			10,
			4
		);
		$this->sql_edit( array( 'mode' => 'monitor' ) );
		$this->check();
		$this->assertSame( array( array( array( 'mode' ), 'changed', 'cron', true ) ), $calls );
	}

	public function test_an_upgrade_write_is_an_audited_write(): void {
		SettingsAuditor::as_upgrade(
			function (): void {
				update_option( Settings::OPTION, array_replace_recursive( Settings::defaults(), array( 'mode' => 'monitor' ) ) );
			}
		);
		$this->assertCount( 1, $this->rows() );
		$this->check();
		$this->assertCount( 1, $this->rows() );
	}
}
