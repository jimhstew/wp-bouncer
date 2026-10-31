<?php
/**
 * WPB-12 red-team findings RT-01 to RT-08: a database writer cannot switch the drift check off or hide a drift.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Audit;

use WPBouncer\Admin\AdminController;
use WPBouncer\Audit\FingerprintRecord;
use WPBouncer\Audit\FingerprintStore;
use WPBouncer\Audit\SettingsDriftMonitor;
use WPBouncer\Installer;
use WPBouncer\Log\BlockLog;
use WPBouncer\Settings;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Audit\SettingsDriftMonitor
 * @covers \WPBouncer\Audit\FingerprintStore
 * @covers \WPBouncer\Audit\FingerprintRecord
 * @covers \WPBouncer\Storage\OptionLock
 * @covers \WPBouncer\Alerts\AlertNotifier
 */
final class DriftRedTeamTest extends IntegrationTestCase {

	/** Set up: a baseline, a clean log and mailbox. */
	public function set_up() {
		parent::set_up();
		$this->fake_request();
		wp_set_current_user( 0 );
		foreach ( array( FingerprintStore::RECORD_OPTION, FingerprintStore::MARKER_OPTION, FingerprintStore::LOCK_OPTION ) as $name ) {
			delete_option( $name );
		}
		delete_transient( FingerprintStore::THROTTLE_TRANSIENT );
		update_option( Settings::OPTION, Settings::defaults() );
		$this->check();
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

	/** Run the cron check. */
	private function check(): void {
		$this->plugin->drift_monitor()->check( SettingsDriftMonitor::TRIGGER_CRON );
	}

	/** @return array<int, array<string, mixed>> */
	private function mails(): array {
		$this->plugin->alerts()->flush();
		return $this->sent_mail();
	}

	/**
	 * Change the settings option behind WordPress's back (SQL).
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

	/**
	 * Write a raw option row.
	 *
	 * @param string $name  Name.
	 * @param string $value Raw text.
	 */
	private function plant_row( string $name, string $value ): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", $name ) ); // phpcs:ignore WordPress.DB
		$wpdb->query( $wpdb->prepare( "INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $name, $value ) ); // phpcs:ignore WordPress.DB
		wp_cache_delete( $name, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
	}

	/** Make every insert into the Activity Log fail. */
	private function break_log_inserts(): callable {
		global $wpdb;
		$wpdb->suppress_errors( true );
		$filter = static function ( $query ) use ( $wpdb ) {
			return str_starts_with( $query, "INSERT INTO `{$wpdb->prefix}bouncer_log`" ) || str_starts_with( $query, "INSERT INTO {$wpdb->prefix}bouncer_log" ) ? 'INSERT INTO wpb_no_such_table (a) VALUES (1)' : $query;
		};
		add_filter( 'query', $filter );
		return $filter;
	}

	/** Undo break_log_inserts(). */
	private function fix_log_inserts( callable $filter ): void {
		remove_filter( 'query', $filter );
	}

	public function test_rt01_a_lock_dated_in_the_future_does_not_block_the_check(): void {
		$this->plant_row( FingerprintStore::LOCK_OPTION, ( time() + DAY_IN_SECONDS ) . '|othertoken' );
		$this->sql_edit( array( 'mode' => 'monitor' ) );
		$this->check();
		$this->assertCount( 1, $this->rows() );
	}

	public function test_rt01_a_garbage_lock_does_not_block_the_check(): void {
		$this->plant_row( FingerprintStore::LOCK_OPTION, 'forever' );
		$this->sql_edit( array( 'mode' => 'monitor' ) );
		$this->check();
		$this->assertCount( 1, $this->rows() );
	}

	public function test_rt02_preset_throttle_transients_do_not_suppress_the_drift_mail(): void {
		$names = array( 'wpb_alert_count', 'wpb_alert_count_critical', 'wpb_alert_count_settings', 'wpb_alert_count_login' );
		foreach ( $names as $name ) {
			set_transient( $name, 999, HOUR_IN_SECONDS );
			update_option( '_transient_timeout_' . $name, time() + YEAR_IN_SECONDS );
		}
		set_transient( 'wpb_alert_uncapped', array( get_current_blog_id() => 50 ), HOUR_IN_SECONDS );
		update_option( '_transient_timeout_wpb_alert_uncapped', time() + YEAR_IN_SECONDS );
		set_transient( 'wpb_alert_settings_notice', array( get_current_blog_id() ), HOUR_IN_SECONDS );
		update_option( '_transient_timeout_wpb_alert_settings_notice', time() + YEAR_IN_SECONDS );

		$this->sql_edit( array( 'alerts' => array( 'enabled' => false ) ) );
		$this->check();
		$this->assertCount( 1, $this->rows() );
		$this->assertCount( 1, $this->mails() );
	}

	public function test_rt02_a_counter_with_a_far_timeout_is_ignored_by_other_alerts_too(): void {
		set_transient( 'wpb_alert_count_critical', 20, HOUR_IN_SECONDS );
		update_option( '_transient_timeout_wpb_alert_count_critical', time() + YEAR_IN_SECONDS );
		$this->plugin->alerts()->on_log_cleared();
		$this->assertCount( 1, $this->mails() );
	}

	public function test_rt03_a_drift_whose_row_failed_is_reported_after_a_later_save(): void {
		$this->sql_edit( array( 'allowlist' => array( '198.51.100.1' ) ) );
		$filter = $this->break_log_inserts();
		update_option( Settings::OPTION, array_replace_recursive( Settings::defaults(), array( 'mode' => 'monitor' ) ) );
		$this->assertCount( 0, $this->rows() );
		$this->fix_log_inserts( $filter );
		$this->empty_log();
		$this->clear_mail();

		$this->check();
		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'allowlist', $rows[0]['reason'] );
		$this->assertCount( 1, $this->mails() );

		$record = FingerprintRecord::from_stored( ( new FingerprintStore() )->load() );
		$this->assertSame( array(), $record->pending, 'cleared once the row is written' );
		$this->empty_log();
		$this->check();
		$this->assertCount( 0, $this->rows(), 'reported once' );
	}

	public function test_rt04_unknown_key_drift_is_not_rebaselined_when_the_row_fails(): void {
		delete_option( FingerprintStore::RECORD_OPTION );
		$filter = $this->break_log_inserts();
		$this->check();
		$this->assertFalse( ( new FingerprintStore() )->load(), 'the record is still absent' );
		$this->fix_log_inserts( $filter );

		$this->check();
		$this->assertCount( 1, $this->rows() );
		$this->assertNotFalse( ( new FingerprintStore() )->load() );
	}

	public function test_rt04_a_missing_log_table_keeps_the_record_untouched(): void {
		global $wpdb;
		delete_option( FingerprintStore::RECORD_OPTION );
		$wpdb->suppress_errors( true );
		$filter = static function ( $query ) use ( $wpdb ) {
			return str_contains( $query, $wpdb->prefix . 'bouncer_log' ) ? str_replace( $wpdb->prefix . 'bouncer_log', 'wpb_missing_log', $query ) : $query;
		};
		add_filter( 'query', $filter );
		$this->check();
		remove_filter( 'query', $filter );
		$this->assertFalse( ( new FingerprintStore() )->load() );
		$this->check();
		$this->assertCount( 1, $this->rows() );
	}

	public function test_rt06_a_throttle_with_a_far_timeout_does_not_stop_the_admin_check(): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		set_transient( FingerprintStore::THROTTLE_TRANSIENT, 1, HOUR_IN_SECONDS );
		update_option( '_transient_timeout_' . FingerprintStore::THROTTLE_TRANSIENT, time() + YEAR_IN_SECONDS );
		$this->sql_edit( array( 'mode' => 'monitor' ) );
		$this->plugin->drift_monitor()->on_admin_init();
		$this->assertCount( 1, $this->rows() );
	}

	public function test_rt06_a_removed_cron_event_is_scheduled_again_by_an_admin_page_load(): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		wp_clear_scheduled_hook( Installer::CRON_HOOK );
		$this->assertFalse( wp_next_scheduled( Installer::CRON_HOOK ) );
		$this->plugin->drift_monitor()->on_admin_init();
		$this->assertNotFalse( wp_next_scheduled( Installer::CRON_HOOK ) );
	}

	public function test_rt07_changed_admin_email_and_recipients_are_named_in_one_row(): void {
		global $wpdb;
		$wpdb->update( $wpdb->options, array( 'option_value' => 'attacker@example.com' ), array( 'option_name' => 'admin_email' ) ); // phpcs:ignore WordPress.DB
		wp_cache_delete( 'alloptions', 'options' );
		wp_cache_delete( 'admin_email', 'options' );
		$this->sql_edit( array( 'alerts' => array( 'recipients' => 'attacker@example.com' ) ) );
		$this->check();
		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'wp.admin_email', $rows[0]['reason'] );
		$this->assertStringContainsString( 'alerts.recipients', $rows[0]['reason'] );
		$this->assertCount( 1, $this->mails() );
	}

	public function test_rt07_a_record_without_the_email_leaves_is_rebaselined_silently(): void {
		$store = new FingerprintStore();
		$old   = FingerprintRecord::from_stored( $store->load() );
		$key   = new \WPBouncer\Audit\FingerprintKey( wp_salt( 'auth' ), get_current_blog_id() );
		$leaves = array_diff_key( $old->leaves, array_flip( \WPBouncer\Audit\SettingsFingerprint::extra_paths() ) );
		$v1     = FingerprintRecord::sealed( $key, 0, $leaves, array(), 1 );
		$store->save( $v1 );
		$this->assertSame( 1, FingerprintRecord::from_stored( $store->load() )->version );

		$this->check();
		$this->assertCount( 0, $this->rows() );
		$this->assertCount( 0, $this->mails() );
		$new = FingerprintRecord::from_stored( $store->load() );
		$this->assertSame( FingerprintRecord::VERSION, $new->version );
		$this->check();
		$this->assertCount( 0, $this->rows() );
	}

	public function test_rt08_a_planted_serialized_object_is_never_unserialized(): void {
		$GLOBALS['wpb_wakeup_flag'] = false;
		$class                      = 'WpbWakeupProbe';
		if ( ! class_exists( $class ) ) {
			eval( 'class WpbWakeupProbe { public function __wakeup() { $GLOBALS["wpb_wakeup_flag"] = true; } }' ); // phpcs:ignore Squiz.PHP.Eval.Discouraged, Generic.PHP.ForbiddenFunctions
		}
		$this->plant_row( FingerprintStore::RECORD_OPTION, 'O:14:"WpbWakeupProbe":0:{}' );
		$this->plant_row( FingerprintStore::MARKER_OPTION, 'O:14:"WpbWakeupProbe":0:{}' );
		$this->check();
		$this->assertFalse( $GLOBALS['wpb_wakeup_flag'], 'no __wakeup' );
		// The marker was unusable, so this counts as a first baseline: silent, and the record is sound again.
		$this->assertCount( 0, $this->rows() );
		$this->assertNotNull( FingerprintRecord::from_stored( ( new FingerprintStore() )->load() ) );

		$this->plant_row( FingerprintStore::RECORD_OPTION, 'O:14:"WpbWakeupProbe":0:{}' );
		$store = new FingerprintStore();
		$store->set_marker( time() );
		$this->check();
		$this->assertFalse( $GLOBALS['wpb_wakeup_flag'] );
		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'fingerprint missing', $rows[0]['reason'] );
	}
}
