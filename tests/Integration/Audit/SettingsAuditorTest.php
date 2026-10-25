<?php
/**
 * WPB-8: settings written outside the admin UI are audited (SB-15 a to g).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Audit;

use WPBouncer\Admin\AdminController;
use WPBouncer\Audit\SettingsAuditor;
use WPBouncer\Installer;
use WPBouncer\Log\BlockLog;
use WPBouncer\Settings;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * Rows, alerts and the action for every write to the settings option.
 *
 * @covers \WPBouncer\Audit\SettingsAuditor
 */
final class SettingsAuditorTest extends IntegrationTestCase {

	/** Set up: a signed-out request with a clean log and mailbox. */
	public function set_up() {
		parent::set_up();
		$this->fake_request();
		wp_set_current_user( 0 );
		$this->plugin->alerts()->flush();
		$this->clear_mail();
		$this->empty_log();
	}

	/** Delete log rows without DDL (TRUNCATE would end the test's transaction). */
	private function empty_log(): void {
		global $wpdb;
		$wpdb->query( "DELETE FROM {$wpdb->prefix}bouncer_log" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Log rows for the settings rule on the current blog.
	 *
	 * @return array<int, array<string, string>>
	 */
	private function rows(): array {
		global $wpdb;
		return (array) ( new BlockLog( $wpdb ) )->query( array( 'rule' => AdminController::SETTINGS_LOG_RULE ) );
	}

	/**
	 * Current stored settings as a full array, with changes merged in.
	 *
	 * @param array<string, mixed> $over Top-level or nested overrides.
	 * @return array<string, mixed>
	 */
	private function with( array $over ): array {
		return Settings::sanitize( array_replace_recursive( $this->plugin->settings()->to_array(), $over ) );
	}

	/** Send queued alerts and return the captured mail. */
	private function flushed_mail(): array {
		$this->plugin->alerts()->flush();
		return $this->sent_mail();
	}

	/**
	 * Record calls of wp_bouncer_settings_changed.
	 *
	 * @param array<int, array<int, mixed>> $calls Receives the argument lists.
	 */
	private function capture_action( array &$calls ): void {
		add_action(
			'wp_bouncer_settings_changed',
			static function ( ...$args ) use ( &$calls ): void {
				$calls[] = $args;
			},
			10,
			4
		);
	}

	/* ---------------- (a) no user ---------------- */

	/** A save with nobody signed in gives one settings alert row, key paths only, a non-blank actor. */
	public function test_a_save_with_no_user_logs_one_row_with_key_paths_and_a_known_actor(): void {
		update_option( Settings::OPTION, $this->with( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) ) );

		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( 'alert', $rows[0]['action'] );
		$this->assertStringContainsString( 'rules.waf.enabled', $rows[0]['reason'] );
		$this->assertMatchesRegularExpression( '/^Settings changed by (cli|unknown)\b/', $rows[0]['reason'] );
	}

	/** Written values never reach the row. */
	public function test_written_values_never_appear_in_the_row(): void {
		update_option( Settings::OPTION, $this->with( array( 'allowlist' => array( '198.51.100.77' ) ) ) );

		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'allowlist', $rows[0]['reason'] );
		$this->assertStringNotContainsString( '198.51.100', $rows[0]['reason'] );
	}

	/* ---------------- (c) UI save ---------------- */

	/** A UI save gives exactly one row and one alert. */
	public function test_a_ui_save_gives_exactly_one_row_and_one_alert(): void {
		$id = self::factory()->user->create(
			array(
				'role'       => 'administrator',
				'user_login' => 'uisaver',
			)
		);
		wp_set_current_user( $id );
		$this->plugin->alerts()->flush();
		$this->clear_mail();
		$this->empty_log();
		$_POST                     = array(
			'rule'     => 'waf',
			'_wpnonce' => wp_create_nonce( 'wp_bouncer_toggle_rule' ),
		);
		$_REQUEST                  = $_POST;
		$_SERVER['REQUEST_METHOD'] = 'POST';

		$this->redirect_of( array( new AdminController( $this->plugin ), 'handle_toggle_rule' ) );

		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertMatchesRegularExpression( '/^Settings changed by uisaver #\d+: /', $rows[0]['reason'] );
		$this->assertCount( 1, $this->flushed_mail() );
	}

	/* ---------------- (d) no change ---------------- */

	/** A no-change save, and a raw-only difference, give no row, no alert and no action. */
	public function test_a_no_change_save_gives_no_row(): void {
		update_option( Settings::OPTION, $this->with( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) ) );
		$this->empty_log();
		$this->plugin->alerts()->flush();
		$this->clear_mail();
		$calls = array();
		$this->capture_action( $calls );

		update_option( Settings::OPTION, $this->with( array() ) );
		// Raw-only difference: an unknown extra key does not change the normalised settings.
		$raw          = get_option( Settings::OPTION );
		$raw['extra'] = 'ignored';
		update_option( Settings::OPTION, $raw );

		$this->assertCount( 0, $this->rows() );
		$this->assertCount( 0, $this->flushed_mail() );
		$this->assertSame( array(), $calls );
	}

	/* ---------------- (g) add, delete, alert, action ---------------- */

	/** Delete then add of a weaker mode gives rows, one firewall alert, and the action with the actor. */
	public function test_delete_then_add_logs_rows_queues_the_alert_and_passes_the_actor(): void {
		$calls = array();
		$this->capture_action( $calls );

		delete_option( Settings::OPTION );
		add_option( Settings::OPTION, $this->with( array( 'mode' => 'monitor' ) ) );

		$rows = $this->rows();
		$this->assertGreaterThanOrEqual( 1, count( $rows ) );
		$this->assertLessThanOrEqual( 2, count( $rows ) );
		$joined = implode( ' ', wp_list_pluck( $rows, 'reason' ) );
		$this->assertStringContainsString( 'mode', $joined );
		$this->assertNotEmpty( $calls );
		foreach ( $calls as $args ) {
			$this->assertCount( 4, $args );
			$this->assertMatchesRegularExpression( '/^(cli|unknown)$/', $args[3] );
		}
		$last = end( $calls );
		$this->assertContains( 'mode', $last[0] );
		$mail = $this->flushed_mail();
		$this->assertNotEmpty( $mail );
		$this->assertStringContainsString( 'irewall', $mail[0]['subject'] . $mail[0]['body'] );
	}

	/** A delete alone is logged under the "settings" path. */
	public function test_a_delete_is_logged_as_settings(): void {
		update_option( Settings::OPTION, $this->with( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) ) );
		$this->empty_log();
		$this->clear_mail();

		delete_option( Settings::OPTION );

		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertMatchesRegularExpression( '/\bsettings\b/', $rows[0]['reason'] );
	}

	/** A risky change queues the firewall_changes alert and fires the action with the actor. */
	public function test_a_risky_change_queues_the_alert_and_fires_the_action_with_the_actor(): void {
		$calls = array();
		$this->capture_action( $calls );
		wp_set_current_user( self::factory()->user->create( array( 'user_login' => 'riskyone' ) ) );

		update_option( Settings::OPTION, $this->with( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) ) );

		$this->assertCount( 1, $calls );
		$this->assertSame( array( 'rules.waf.enabled' ), $calls[0][0] );
		$this->assertMatchesRegularExpression( '/^riskyone #\d+$/', $calls[0][3] );
		$mail = $this->flushed_mail();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'Firewall settings changed', $mail[0]['subject'] );
	}

	/** A non-risky change is logged and fires the action, but queues no alert. */
	public function test_a_non_risky_change_queues_no_alert(): void {
		$this->set_settings( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) );
		$this->clear_mail();
		$calls = array();
		$this->capture_action( $calls );

		update_option( Settings::OPTION, $this->with( array( 'rules' => array( 'waf' => array( 'enabled' => true ) ) ) ) );

		$this->assertCount( 1, $this->rows() );
		$this->assertCount( 1, $calls );
		$this->assertCount( 0, $this->flushed_mail() );
	}

	/* ---------------- double registration ---------------- */

	/** Exactly one auditor is hooked, and the fixture helper restores it. */
	public function test_exactly_one_auditor_is_hooked_and_the_fixture_helper_restores_it(): void {
		$count = static function (): int {
			global $wp_filter;
			$n = 0;
			foreach ( $wp_filter[ 'update_option_' . Settings::OPTION ]->callbacks ?? array() as $callbacks ) {
				foreach ( $callbacks as $cb ) {
					if ( is_array( $cb['function'] ) && $cb['function'][0] instanceof SettingsAuditor ) {
						++$n;
					}
				}
			}
			return $n;
		};
		$this->assertSame( 1, $count() );

		$this->set_settings( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) );

		$this->assertSame( 1, $count(), 'without_settings_audit() put the hooks back' );
		$this->assertCount( 0, $this->rows(), 'and the fixture write was not audited' );
	}

	/** A second registered auditor must not double the row (the row count stays 1). */
	public function test_a_second_auditor_instance_does_not_double_the_log(): void {
		( new SettingsAuditor( $this->plugin ) )->register();

		update_option( Settings::OPTION, $this->with( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) ) );

		$this->assertCount( 1, $this->rows() );
		$this->assertCount( 1, $this->flushed_mail() );
	}

	/* ---------------- alert gating on the old value ---------------- */

	/** Old alerts off, new on: nothing is sent. */
	public function test_alerts_off_before_and_on_after_sends_nothing(): void {
		$this->set_settings( array( 'alerts' => array( 'enabled' => false ) ) );
		$this->clear_mail();

		update_option(
			Settings::OPTION,
			$this->with(
				array(
					'alerts' => array( 'enabled' => true ),
					'rules'  => array( 'waf' => array( 'enabled' => false ) ),
				)
			)
		);

		$this->assertCount( 1, $this->rows() );
		$this->assertCount( 0, $this->flushed_mail() );
	}

	/** Old alerts on, new off: the alert is still queued. */
	public function test_alerts_on_before_and_off_after_still_sends(): void {
		$this->set_settings( array( 'alerts' => array( 'enabled' => true ) ) );
		$this->clear_mail();

		update_option( Settings::OPTION, $this->with( array( 'alerts' => array( 'enabled' => false ) ) ) );

		$this->assertCount( 1, $this->flushed_mail() );
	}

	/* ---------------- the clear-log row text ---------------- */

	/** The "Activity log cleared by X" row has the plain actor and no context suffix. */
	public function test_the_log_cleared_row_text_has_no_context_suffix(): void {
		$id = self::factory()->user->create(
			array(
				'role'       => 'administrator',
				'user_login' => 'clearer',
			)
		);
		wp_set_current_user( $id );
		$_POST                     = array( '_wpnonce' => wp_create_nonce( 'wp_bouncer_clear_log' ) );
		$_REQUEST                  = $_POST;
		$_SERVER['REQUEST_METHOD'] = 'POST';
		add_filter(
			'query',
			static function ( $sql ) {
				return (string) preg_replace( '/^\s*TRUNCATE TABLE\s+(\S+)/i', 'DELETE FROM $1', (string) $sql );
			}
		);

		$this->redirect_of( array( new AdminController( $this->plugin ), 'handle_clear_log' ) );

		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertMatchesRegularExpression( '/^Activity log cleared by clearer #\d+$/', $rows[0]['reason'] );
	}

	/* ---------------- (f) multisite ---------------- */

	/** A write inside switch_to_blog() logs to that site's table and leaves the main site's settings alone. */
	public function test_a_switched_blog_write_logs_to_that_sites_table_only(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		global $wpdb;
		$this->use_real_ddl();
		$site = self::factory()->blog->create();
		switch_to_blog( $site );
		Installer::activate();
		update_option( Settings::OPTION, Settings::defaults() );
		$wpdb->query( "DELETE FROM {$wpdb->prefix}bouncer_log" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		restore_current_blog();
		$wpdb->query( 'COMMIT' );
		$this->empty_log();
		$before = $this->plugin->settings()->to_array();

		switch_to_blog( $site );
		$new                            = Settings::defaults();
		$new['rules']['waf']['enabled'] = false;
		update_option( Settings::OPTION, $new );
		$on_site = $this->rows();
		restore_current_blog();

		$this->assertCount( 1, $on_site, "site $site has the row" );
		$this->assertStringContainsString( 'rules.waf.enabled', $on_site[0]['reason'] );
		$this->assertCount( 0, $this->rows(), 'the main site has none' );
		$this->assertSame( $before, $this->plugin->settings()->to_array(), 'the main site settings are unchanged' );
	}
}
