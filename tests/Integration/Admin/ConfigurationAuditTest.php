<?php
/**
 * The configuration audit (S13): one log row, one alert and one action per real settings change.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\SetupNotices;
use WPBouncer\Alerts\AlertNotifier;
use WPBouncer\Log\BlockLog;
use WPBouncer\Plugin;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * Settings audit rows, alerts and hook.
 *
 * @covers \WPBouncer\Admin\AdminController
 * @covers \WPBouncer\Alerts\AlertNotifier
 */
final class ConfigurationAuditTest extends IntegrationTestCase {

	/**
	 * Controller under test.
	 *
	 * @var AdminController
	 */
	private $admin;

	/** Set up. */
	public function set_up() {
		parent::set_up();
		$this->admin = new AdminController( $this->plugin );
		$this->fake_request();
		// TRUNCATE ends the test's transaction and would leave this test's users behind.
		add_filter(
			'query',
			static function ( $sql ) {
				return (string) preg_replace( '/^\s*TRUNCATE TABLE\s+(\S+)/i', 'DELETE FROM $1', (string) $sql );
			}
		);
		$id = self::factory()->user->create(
			array(
				'role'       => 'administrator',
				'user_login' => 'auditor',
			)
		);
		wp_set_current_user( $id );
		// Fixture users queue their own alerts on the shared notifier; start clean.
		$this->plugin->alerts()->flush();
		$this->clear_mail();
		$this->empty_log();
		delete_option( AlertNotifier::DISABLED_REMINDER_OPTION );
	}

	/**
	 * Prepare a POST with a valid nonce.
	 *
	 * @param string               $action Nonce action.
	 * @param array<string, mixed> $post   Fields.
	 */
	private function post( string $action, array $post ): void {
		$post['_wpnonce']          = wp_create_nonce( $action );
		$_POST                     = $post;
		$_REQUEST                  = $post;
		$_SERVER['REQUEST_METHOD'] = 'POST';
	}

	/** Delete log rows without DDL (TRUNCATE would end the test's transaction). */
	private function empty_log(): void {
		global $wpdb;
		$wpdb->query( "DELETE FROM {$wpdb->prefix}bouncer_log" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Log rows for one rule.
	 *
	 * @param string $rule Rule id.
	 * @return array<int, array<string, string>>
	 */
	private function rows( string $rule ): array {
		global $wpdb;
		return (array) ( new BlockLog( $wpdb ) )->query( array( 'rule' => $rule ) );
	}

	/**
	 * Addresses a captured mail went to.
	 *
	 * @param array<string, mixed> $mail One entry of sent_mail().
	 * @return string[]
	 */
	private function recipients_of( array $mail ): array {
		return array_map( 'strval', wp_list_pluck( (array) $mail['to'], 0 ) );
	}

	/**
	 * Save the General tab and send queued alerts.
	 *
	 * @param array<string, mixed> $fields Submitted wp_bouncer fields.
	 */
	private function save_general( array $fields ): void {
		$this->post(
			'wp_bouncer_save',
			array(
				'tab'        => 'general',
				'wp_bouncer' => $fields,
			)
		);
		$this->redirect_of( array( $this->admin, 'handle_save' ) );
		$this->plugin->alerts()->flush();
	}

	/* ---------------- one row, one alert, one action ---------------- */

	/** Toggling a rule off gives one row one alert and the action. */
	public function test_toggling_a_rule_off_gives_one_row_one_alert_and_the_action(): void {
		$calls = array();
		add_action(
			'wp_bouncer_settings_changed',
			static function ( $changes, $old, $after ) use ( &$calls ): void {
				$calls[] = array( $changes, $old, $after );
			},
			10,
			3
		);
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'waf' ) );

		$this->redirect_of( array( $this->admin, 'handle_toggle_rule' ) );
		$this->plugin->alerts()->flush();

		$rows = $this->rows( 'settings' );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'alert', $rows[0]['action'] );
		$this->assertStringContainsString( 'rules.waf.enabled', $rows[0]['reason'] );
		$this->assertStringStartsWith( 'Settings changed by auditor:', $rows[0]['reason'] );
		$this->assertCount( 0, $this->rows( 'alerts' ), 'the audit row is not written twice' );

		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'Firewall settings changed', $mail[0]['subject'] );
		$this->assertStringContainsString( 'rules.waf.enabled', $mail[0]['body'] );
		$this->assertStringContainsString( 'auditor', $mail[0]['body'] );

		$this->assertCount( 1, $calls );
		$this->assertSame( array( 'rules.waf.enabled' ), $calls[0][0] );
		$this->assertTrue( $calls[0][1]['rules']['waf']['enabled'] );
		$this->assertFalse( $calls[0][2]['rules']['waf']['enabled'] );
	}

	/** Turning a rule on is logged but not emailed. */
	public function test_turning_a_rule_on_is_logged_but_not_emailed(): void {
		$this->set_settings( array( 'rules' => array( 'waf' => array( 'enabled' => false ) ) ) );
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'waf' ) );

		$this->redirect_of( array( $this->admin, 'handle_toggle_rule' ) );
		$this->plugin->alerts()->flush();

		$this->assertCount( 1, $this->rows( 'settings' ) );
		$this->assertCount( 0, $this->sent_mail() );
	}

	/** The row and the email name the keys but never the values. */
	public function test_the_row_and_the_email_name_the_keys_but_never_the_values(): void {
		$this->save_general( array( 'allowlist' => "198.51.100.77\n198.51.100.78" ) );

		$rows = $this->rows( 'settings' );
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'allowlist', $rows[0]['reason'] );
		$this->assertStringNotContainsString( '198.51.100', $rows[0]['reason'] );

		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'allowlist', $mail[0]['body'] );
		$this->assertStringNotContainsString( '198.51.100', $mail[0]['subject'] . $mail[0]['body'] );
	}

	/** Saving without a change gives no row no alert and no action. */
	public function test_saving_without_a_change_gives_no_row_no_alert_and_no_action(): void {
		$fired = 0;
		$this->save_general( array() );
		$this->empty_log();
		$this->clear_mail();
		add_action(
			'wp_bouncer_settings_changed',
			static function () use ( &$fired ): void {
				++$fired;
			}
		);

		$this->save_general( array() );

		$this->assertCount( 0, $this->rows( 'settings' ) );
		$this->assertCount( 0, $this->sent_mail() );
		$this->assertSame( 0, $fired );
	}

	/** A firewall changes alert can be switched off. */
	public function test_a_firewall_changes_alert_can_be_switched_off(): void {
		$this->set_settings( array( 'alerts' => array( 'firewall_changes' => false ) ) );
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'waf' ) );

		$this->redirect_of( array( $this->admin, 'handle_toggle_rule' ) );
		$this->plugin->alerts()->flush();

		$this->assertCount( 1, $this->rows( 'settings' ), 'the audit row is always written' );
		$this->assertCount( 0, $this->sent_mail() );
	}

	/** Block ip gives one row. */
	public function test_block_ip_gives_one_row(): void {
		$_GET     = array(
			'ip'       => '198.51.100.99',
			'_wpnonce' => wp_create_nonce( 'wp_bouncer_block_ip|198.51.100.99' ),
		);
		$_POST    = array();
		$_REQUEST = $_GET; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$this->redirect_of( array( $this->admin, 'handle_block_ip' ) );

		$rows = $this->rows( 'settings' );
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'rules.ip_blocklist.ips', $rows[0]['reason'] );
		$this->assertStringNotContainsString( '198.51.100.99', $rows[0]['reason'] );
	}

	/** Ip setup gives one row. */
	public function test_ip_setup_gives_one_row(): void {
		$this->set_settings(
			array(
				'ip_source'       => 'x_real_ip',
				'trusted_proxies' => array(),
			)
		);
		$this->empty_log();
		$this->post( SetupNotices::NONCE_ACTION, array( 'fix' => 'use_remote_addr' ) );

		$this->redirect_of( array( $this->admin, 'handle_ip_setup' ) );

		$rows = $this->rows( 'settings' );
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'ip_source', $rows[0]['reason'] );
	}

	/* ---------------- one save cannot mute or redirect its own alert ---------------- */

	/** A save that turns alerts off and changes the mode still emails the old recipients. */
	public function test_a_save_that_turns_alerts_off_and_changes_the_mode_still_emails_the_old_recipients(): void {
		$this->set_settings(
			array(
				'alerts' => array(
					'enabled'    => true,
					'recipients' => array( 'old@example.org' ),
				),
			)
		);

		// No alerts fields posted: alerts switch off and the recipients clear.
		$this->save_general( array( 'mode' => 'monitor' ) );

		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail, 'the save did not mute its own alert' );
		$this->assertContains( 'old@example.org', $this->recipients_of( $mail[0] ) );
		$this->assertStringContainsString( 'alerts.enabled', $mail[0]['body'] );
		$this->assertStringContainsString( 'mode', $mail[0]['body'] );
		$this->assertFalse( $this->plugin->settings()->get( 'alerts' )['enabled'] );
	}

	/** A save that changes recipients and mode emails old and new addresses. */
	public function test_a_save_that_changes_recipients_and_mode_emails_old_and_new_addresses(): void {
		$this->set_settings( array( 'alerts' => array( 'recipients' => array( 'old@example.org' ) ) ) );

		$this->save_general(
			array(
				'mode'   => 'monitor',
				'alerts' => array(
					'enabled'          => '1',
					'firewall_changes' => '1',
					'recipients'       => 'new@example.org',
				),
			)
		);

		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$to = $this->recipients_of( $mail[0] );
		$this->assertContains( 'old@example.org', $to );
		$this->assertContains( 'new@example.org', $to );
		$this->assertStringContainsString( 'alerts.recipients', $mail[0]['body'] );
	}

	/** The logged ip is resolved with the settings in force before the save. */
	public function test_the_logged_ip_is_resolved_with_the_settings_in_force_before_the_save(): void {
		$this->fake_request(
			array(
				'REMOTE_ADDR'    => '203.0.113.9',
				'HTTP_X_REAL_IP' => '198.51.100.7',
			)
		);

		$this->save_general(
			array(
				'ip_source'       => 'x_real_ip',
				'trusted_proxies' => '203.0.113.9',
			)
		);

		$rows = $this->rows( 'settings' );
		$this->assertCount( 1, $rows );
		$this->assertSame( '203.0.113.9', $rows[0]['ip'], 'the pre-save IP, not the one the new source would give' );
	}

	/**
	 * The General tab fields that leave every alert and default as it is.
	 *
	 * @param array<string, mixed> $extra Fields to add.
	 * @return array<string, mixed>
	 */
	private function neutral_general( array $extra ): array {
		return array_merge(
			array(
				'alerts' => array(
					'enabled'          => '1',
					'new_admin'        => '1',
					'plugin_changes'   => '1',
					'firewall_changes' => '1',
				),
			),
			$extra
		);
	}

	/** Lowering the log retention alerts; raising it is logged only. */
	public function test_lowering_the_log_retention_alerts_and_raising_it_does_not(): void {
		$this->save_general( $this->neutral_general( array( 'log_retention_days' => '60' ) ) );
		$this->assertCount( 1, $this->rows( 'settings' ) );
		$this->assertCount( 0, $this->sent_mail(), 'raising is log-only' );

		$this->save_general( $this->neutral_general( array( 'log_retention_days' => '5' ) ) );
		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'log_retention_days', $mail[0]['body'] );
	}

	/** Lowering the traffic retention alerts; raising it is logged only. */
	public function test_lowering_the_traffic_retention_alerts_and_raising_it_does_not(): void {
		$field = array(
			'tab'        => 'traffic',
			'wp_bouncer' => array(),
		);
		$this->set_settings( array( 'traffic' => array( 'retention_days' => 3 ) ) );
		$field['wp_bouncer'] = array( 'traffic' => array( 'retention_days' => '5' ) );
		$this->post( 'wp_bouncer_save', $field );
		$this->redirect_of( array( $this->admin, 'handle_save' ) );
		$this->plugin->alerts()->flush();
		$this->assertCount( 0, $this->sent_mail(), 'raising is log-only' );

		$field['wp_bouncer'] = array( 'traffic' => array( 'retention_days' => '2' ) );
		$this->post( 'wp_bouncer_save', $field );
		$this->redirect_of( array( $this->admin, 'handle_save' ) );
		$this->plugin->alerts()->flush();
		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'traffic.retention_days', $mail[0]['body'] );
	}

	/** A shorter blocklist alerts. */
	public function test_a_shrinking_blocklist_alerts(): void {
		$this->set_settings( array( 'rules' => array( 'ip_blocklist' => array( 'ips' => array( '198.51.100.1', '198.51.100.2' ) ) ) ) );
		$this->post(
			'wp_bouncer_save',
			array(
				'tab'        => 'rules',
				'wp_bouncer' => array(
					'rules' => array(
						'ip_blocklist' => array(
							'enabled' => '1',
							'ips'     => '198.51.100.1',
						),
					),
				),
			)
		);
		$this->redirect_of( array( $this->admin, 'handle_save' ) );
		$this->plugin->alerts()->flush();

		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'rules.ip_blocklist.ips', $mail[0]['body'] );
	}

	/** The first claim is won exactly once, even when the option is not in the object cache. */
	public function test_the_first_claim_is_won_once(): void {
		$first  = $this->disabled_notifier();
		$second = $this->disabled_notifier();
		$first->maybe_remind_disabled();
		wp_cache_delete( AlertNotifier::DISABLED_REMINDER_OPTION, 'options' );
		$second->maybe_remind_disabled();
		$first->flush();
		$second->flush();

		$this->assertCount( 1, $this->sent_mail() );
		$this->assertNotFalse( get_option( AlertNotifier::DISABLED_REMINDER_OPTION ), 'reads stay coherent after the direct write' );
	}

	/* ---------------- clearing the log ---------------- */

	/** Clearing the log leaves a fresh row and alerts. */
	public function test_clearing_the_log_leaves_a_fresh_row_and_alerts(): void {
		$this->post( 'wp_bouncer_clear_log', array() );

		$this->redirect_of( array( $this->admin, 'handle_clear_log' ) );
		$this->plugin->alerts()->flush();

		$rows = $this->rows( 'settings' );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'Activity log cleared by auditor', $rows[0]['reason'] );
		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'Activity Log cleared', $mail[0]['subject'] );
	}

	/** Clearing the log with firewall alerts off still leaves the row. */
	public function test_clearing_the_log_with_firewall_alerts_off_still_leaves_the_row(): void {
		$this->set_settings( array( 'alerts' => array( 'firewall_changes' => false ) ) );
		$this->post( 'wp_bouncer_clear_log', array() );

		$this->redirect_of( array( $this->admin, 'handle_clear_log' ) );
		$this->plugin->alerts()->flush();

		$this->assertCount( 1, $this->rows( 'settings' ) );
		$this->assertCount( 0, $this->sent_mail() );
	}

	/* ---------------- multisite ---------------- */

	/** On multisite the network admin also gets firewall alerts. */
	public function test_on_multisite_the_network_admin_also_gets_firewall_alerts(): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		update_site_option( 'admin_email', 'network@example.org' );
		$this->set_settings( array( 'alerts' => array( 'recipients' => array( 'site@example.org' ) ) ) );
		$this->clear_mail();
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'waf' ) );

		$this->redirect_of( array( $this->admin, 'handle_toggle_rule' ) );
		$this->plugin->alerts()->flush();

		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$to = $this->recipients_of( $mail[0] );
		$this->assertContains( 'site@example.org', $to );
		$this->assertContains( 'network@example.org', $to );
	}

	/* ---------------- WP_BOUNCER_DISABLE reminder ---------------- */

	/**
	 * A notifier that sees the emergency switch as on or off.
	 *
	 * @param bool $disabled Whether WP_BOUNCER_DISABLE counts as set.
	 */
	private function disabled_notifier( bool $disabled = true ): AlertNotifier {
		return new AlertNotifier(
			$this->plugin,
			static function () use ( $disabled ): bool {
				return $disabled;
			}
		);
	}

	/** The disabled reminder is sent once a day. */
	public function test_the_disabled_reminder_is_sent_once_a_day(): void {
		$notifier = $this->disabled_notifier();

		$notifier->maybe_remind_disabled();
		$notifier->maybe_remind_disabled();
		$notifier->flush();

		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'WP_BOUNCER_DISABLE', $mail[0]['subject'] );

		// Another request (a second notifier) in the same day stays quiet.
		$this->clear_mail();
		$other = $this->disabled_notifier();
		$other->maybe_remind_disabled();
		$other->flush();
		$this->assertCount( 0, $this->sent_mail() );

		// A day later the slot can be claimed again, by exactly one of two racing requests.
		update_option( AlertNotifier::DISABLED_REMINDER_OPTION, (string) ( time() - DAY_IN_SECONDS - 5 ), false );
		$first  = $this->disabled_notifier();
		$second = $this->disabled_notifier();
		$first->maybe_remind_disabled();
		$second->maybe_remind_disabled();
		$first->flush();
		$second->flush();
		$this->assertCount( 1, $this->sent_mail(), 'a new day, one new reminder' );
	}

	/** No reminder while the firewall is on. */
	public function test_no_reminder_while_the_firewall_is_on(): void {
		$notifier = $this->disabled_notifier( false );

		$notifier->maybe_remind_disabled();
		$notifier->flush();

		$this->assertCount( 0, $this->sent_mail() );
		$this->assertFalse( get_option( AlertNotifier::DISABLED_REMINDER_OPTION ) );
	}

	/** The admin init reminder needs a signed in manager. */
	public function test_the_admin_init_reminder_needs_a_signed_in_manager(): void {
		wp_set_current_user( 0 );
		$notifier = $this->disabled_notifier();
		$notifier->on_admin_init();
		$this->assertFalse( get_option( AlertNotifier::DISABLED_REMINDER_OPTION ), 'a visitor request does not send it' );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		$notifier->on_admin_init();
		$this->assertFalse( get_option( AlertNotifier::DISABLED_REMINDER_OPTION ), 'neither does a subscriber' );

		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$notifier->on_admin_init();
		$this->assertNotFalse( get_option( AlertNotifier::DISABLED_REMINDER_OPTION ) );
	}

	/** The reminder runs from admin init and the daily job only. */
	public function test_the_reminder_runs_from_admin_init_and_the_daily_job_only(): void {
		$this->assertNotFalse( has_action( 'admin_init', array( $this->plugin->alerts(), 'on_admin_init' ) ) );

		$property = new \ReflectionProperty( Plugin::class, 'alerts' );
		$original = $property->getValue( $this->plugin );
		$property->setValue( $this->plugin, $this->disabled_notifier() );
		try {
			$this->plugin->daily_maintenance();
			$this->assertNotFalse( get_option( AlertNotifier::DISABLED_REMINDER_OPTION ), 'the daily job sends the reminder' );
		} finally {
			$property->setValue( $this->plugin, $original );
		}
	}
}
