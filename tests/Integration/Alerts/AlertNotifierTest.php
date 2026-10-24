<?php
/**
 * Email alerts through the real WordPress hooks and mail function.
 *
 * Mail is captured by the test library's mock PHPMailer. Every test builds its
 * own notifier so events queued by the plugin's shared instance (which reacts
 * to the same hooks) cannot leak in.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Alerts;

use WPBouncer\Alerts\AlertNotifier;
use WPBouncer\Log\BlockLog;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Alerts\AlertNotifier
 */
final class AlertNotifierTest extends IntegrationTestCase {

	/** @var AlertNotifier */
	private $notifier;

	public function set_up() {
		parent::set_up();
		// Core's upgrader_process_complete callbacks live here.
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		$this->fake_request();
		$this->notifier = new AlertNotifier( $this->plugin );
		$this->notifier->register();
		// Users created by the fixtures below must not themselves trigger mail we then count.
		$this->clear_mail();
	}

	/** Flush and return the mail sent. */
	private function flush(): array {
		$this->notifier->flush();
		return $this->sent_mail();
	}

	/** Create a user without leaving alert events behind. */
	private function quiet_user( string $role ): \WP_User {
		$id = self::factory()->user->create( array( 'role' => $role ) );
		$this->notifier->flush();
		$this->clear_mail();
		return get_user_by( 'id', $id );
	}

	/** Change admin_email without keeping core's own notification mail. */
	private function set_admin_email( string $email ): void {
		update_option( 'admin_email', $email );
		$this->clear_mail();
	}

	private function subject( array $mail, int $i = 0 ): string {
		return (string) $mail[ $i ]['subject'];
	}

	private function alert_rows(): array {
		global $wpdb;
		return (array) ( new BlockLog( $wpdb ) )->query( array( 'rule' => 'alerts' ) );
	}

	/* ---------------- administrators ---------------- */

	public function test_creating_an_administrator_sends_exactly_one_email(): void {
		$id = self::factory()->user->create( array( 'role' => 'administrator', 'user_login' => 'newadmin', 'user_email' => 'newadmin@example.org' ) );

		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'New administrator account created', $this->subject( $mail ) );
		$this->assertStringContainsString( 'Username: newadmin, email: newadmin@example.org, user ID ' . $id, $mail[0]['body'] );
	}

	public function test_the_activity_log_row_has_no_email_address(): void {
		self::factory()->user->create( array( 'role' => 'administrator', 'user_login' => 'newadmin2', 'user_email' => 'newadmin2@example.org' ) );
		$this->flush();

		$rows = $this->alert_rows();
		$this->assertNotEmpty( $rows );
		$this->assertStringContainsString( 'newadmin2', $rows[0]['reason'] );
		$this->assertStringNotContainsString( 'newadmin2@example.org', $rows[0]['reason'] );
	}

	public function test_promoting_a_user_sends_one_email(): void {
		$user = $this->quiet_user( 'editor' );

		$user->set_role( 'administrator' );
		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'Account promoted to administrator', $this->subject( $mail ) );
	}

	public function test_adding_the_administrator_role_sends_one_email(): void {
		$user = $this->quiet_user( 'subscriber' );

		$user->add_role( 'administrator' );
		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'Account given the administrator role', $this->subject( $mail ) );
	}

	public function test_a_custom_role_that_can_manage_options_counts_as_an_administrator(): void {
		add_role( 'site_manager', 'Site manager', array( 'read' => true, 'manage_options' => true ) );
		$user = $this->quiet_user( 'subscriber' );

		$user->set_role( 'site_manager' );
		$mail = $this->flush();

		remove_role( 'site_manager' );
		$this->assertCount( 1, $mail );
	}

	public function test_creating_a_subscriber_sends_nothing(): void {
		self::factory()->user->create( array( 'role' => 'subscriber' ) );

		$this->assertCount( 0, $this->flush() );
		$this->assertCount( 0, $this->alert_rows() );
	}

	public function test_other_non_admin_roles_send_nothing(): void {
		foreach ( array( 'editor', 'author', 'contributor' ) as $role ) {
			self::factory()->user->create( array( 'role' => $role ) );
		}

		$this->assertCount( 0, $this->flush() );
	}

	public function test_demoting_an_administrator_sends_nothing(): void {
		$admin = $this->quiet_user( 'administrator' );

		$admin->set_role( 'subscriber' );

		$this->assertCount( 0, $this->flush() );
	}

	public function test_setting_administrator_again_on_an_administrator_sends_nothing(): void {
		$admin = $this->quiet_user( 'administrator' );

		$admin->set_role( 'administrator' );

		$this->assertCount( 0, $this->flush() );
	}

	public function test_granting_super_admin_sends_one_email(): void {
		$user = $this->quiet_user( 'subscriber' );

		do_action( 'granted_super_admin', $user->ID );
		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'network super admin', $this->subject( $mail ) );
	}

	public function test_two_administrators_in_one_request_are_one_email_with_both_lines(): void {
		self::factory()->user->create( array( 'role' => 'administrator', 'user_login' => 'adm_one' ) );
		self::factory()->user->create( array( 'role' => 'administrator', 'user_login' => 'adm_two' ) );

		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( '2 security events including a new administrator', $this->subject( $mail ) );
		$this->assertStringContainsString( 'adm_one', $mail[0]['body'] );
		$this->assertStringContainsString( 'adm_two', $mail[0]['body'] );
	}

	public function test_admin_alerts_can_be_switched_off_separately(): void {
		$this->set_settings( array( 'alerts' => array( 'new_admin' => false ) ) );

		self::factory()->user->create( array( 'role' => 'administrator' ) );
		do_action( 'activated_plugin', 'hello.php', false );
		$mail = $this->flush();

		$this->assertCount( 1, $mail, 'only the plugin alert remains' );
		$this->assertStringContainsString( 'Plugin activated', $this->subject( $mail ) );
	}

	/* ---------------- plugins ---------------- */

	public function test_activating_a_plugin_sends_one_email(): void {
		do_action( 'activated_plugin', 'hello.php', false );

		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'Plugin activated:', $this->subject( $mail ) );
		$this->assertStringContainsString( 'hello.php', $mail[0]['body'] );
	}

	public function test_network_wide_activation_is_mentioned(): void {
		do_action( 'activated_plugin', 'hello.php', true );

		$mail = $this->flush();

		$this->assertStringContainsString( 'network-wide', $mail[0]['body'] );
	}

	public function test_deactivating_a_plugin_sends_one_email(): void {
		do_action( 'deactivated_plugin', 'hello.php', false );

		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'Plugin deactivated:', $this->subject( $mail ) );
	}

	public function test_deactivating_wp_bouncer_itself_says_so(): void {
		do_action( 'deactivated_plugin', plugin_basename( $this->plugin->file() ), false );

		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'WP Bouncer itself was deactivated', $this->subject( $mail ) );
	}

	public function test_deleting_a_plugin_sends_one_email_only_when_it_was_deleted(): void {
		do_action( 'deleted_plugin', 'gone/gone.php', false );
		$this->assertCount( 0, $this->flush(), 'a failed delete is not an alert' );

		do_action( 'deleted_plugin', 'gone/gone.php', true );
		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'Plugin deleted: gone/gone.php', $this->subject( $mail ) );
	}

	public function test_plugin_change_alerts_can_be_switched_off(): void {
		$this->set_settings( array( 'alerts' => array( 'plugin_changes' => false ) ) );

		do_action( 'activated_plugin', 'hello.php', false );
		do_action( 'deactivated_plugin', 'hello.php', false );
		do_action( 'deleted_plugin', 'hello.php', true );

		$this->assertCount( 0, $this->flush() );
	}

	public function test_installing_and_activating_in_one_request_is_one_email(): void {
		$upgrader = new class() {
			public function plugin_info() {
				return 'hello.php';
			}
		};

		do_action( 'upgrader_process_complete', $upgrader, array( 'type' => 'plugin', 'action' => 'install' ) );
		do_action( 'activated_plugin', 'hello.php', false );
		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( '2 security events', $this->subject( $mail ) );
		$this->assertStringContainsString( 'Plugin installed:', $mail[0]['body'] );
		$this->assertStringContainsString( 'Plugin activated:', $mail[0]['body'] );
	}

	public function test_installing_an_unknown_plugin_still_alerts(): void {
		do_action( 'upgrader_process_complete', new \stdClass(), array( 'type' => 'plugin', 'action' => 'install' ) );

		$mail = $this->flush();

		$this->assertStringContainsString( 'Plugin installed: unknown', $this->subject( $mail ) );
	}

	public function test_plugin_updates_are_silent_by_default_and_alert_when_enabled(): void {
		$hook = array( 'type' => 'plugin', 'action' => 'update', 'plugins' => array( 'hello.php', 'other/other.php' ) );

		do_action( 'upgrader_process_complete', new \stdClass(), $hook );
		$this->assertCount( 0, $this->flush() );

		$this->set_settings( array( 'alerts' => array( 'plugin_updates' => true ) ) );
		do_action( 'upgrader_process_complete', new \stdClass(), $hook );
		$mail = $this->flush();

		$this->assertCount( 1, $mail, 'two plugins updated at once are still one email' );
		$this->assertStringContainsString( 'Plugin updated:', $mail[0]['body'] );
		$this->assertStringContainsString( 'other/other.php', $mail[0]['body'] );
	}

	public function test_single_plugin_update_hook_extra_is_understood(): void {
		$this->set_settings( array( 'alerts' => array( 'plugin_updates' => true ) ) );

		do_action( 'upgrader_process_complete', new \stdClass(), array( 'type' => 'plugin', 'action' => 'update', 'plugin' => 'hello.php' ) );

		$this->assertCount( 1, $this->flush() );
	}

	public function test_theme_and_core_upgrades_are_ignored(): void {
		do_action( 'upgrader_process_complete', new \stdClass(), array( 'type' => 'theme', 'action' => 'update', 'themes' => array( 'x' ) ) );
		do_action( 'upgrader_process_complete', new \stdClass(), array( 'type' => 'core', 'action' => 'update' ) );
		do_action( 'upgrader_process_complete', new \stdClass(), 'garbage' );

		$this->assertCount( 0, $this->flush() );
	}

	/* ---------------- sending, logging, throttle ---------------- */

	public function test_flush_with_nothing_queued_sends_nothing_and_does_not_count(): void {
		$this->assertCount( 0, $this->flush() );
		$this->assertFalse( get_transient( 'wpb_alert_count' ) );
	}

	public function test_flushing_twice_does_not_resend(): void {
		do_action( 'activated_plugin', 'hello.php', false );

		$this->notifier->flush();
		$this->notifier->flush();

		$this->assertCount( 1, $this->sent_mail() );
	}

	public function test_each_event_is_written_to_the_activity_log_with_context(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.77', 'REQUEST_URI' => '/wp-admin/plugins.php', 'REQUEST_METHOD' => 'POST', 'HTTP_USER_AGENT' => 'TestAgent/1' ) );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator', 'user_login' => 'boss' ) ) );
		$this->notifier->flush();
		$this->clear_mail();

		do_action( 'activated_plugin', 'hello.php', false );
		do_action( 'deactivated_plugin', 'other/other.php', false );
		$this->notifier->flush();

		$rows = $this->alert_rows();
		$this->assertCount( 3, $rows, 'the admin creation, plus two plugin events' );
		$row = $rows[0];
		$this->assertSame( 'alerts', $row['rule'] );
		$this->assertSame( 'alert', $row['action'] );
		$this->assertSame( '198.51.100.77', $row['ip'] );
		$this->assertSame( 'POST', $row['method'] );
		$this->assertSame( '/wp-admin/plugins.php', $row['uri'] );
		$this->assertSame( 'TestAgent/1', $row['user_agent'] );
		$this->assertStringContainsString( 'by boss (user ID', $row['reason'] );
	}

	public function test_the_email_names_the_actor_and_origin(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '198.51.100.77', 'HTTP_USER_AGENT' => 'TestAgent/1' ) );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'editor', 'user_login' => 'ed' ) ) );
		$this->notifier->flush();
		$this->clear_mail();

		do_action( 'activated_plugin', 'hello.php', false );
		$mail = $this->flush();

		$this->assertStringContainsString( 'Done by:    ed (user ID', $mail[0]['body'] );
		$this->assertStringContainsString( 'From IP:    198.51.100.77', $mail[0]['body'] );
		$this->assertStringContainsString( 'Browser:    TestAgent/1', $mail[0]['body'] );
		$this->assertStringContainsString( 'tab=general#wpb-alerts', $mail[0]['body'] );
	}

	public function test_with_no_logged_in_user_the_email_says_so(): void {
		wp_set_current_user( 0 );
		do_action( 'activated_plugin', 'hello.php', false );

		$mail = $this->flush();

		$this->assertStringContainsString( 'no logged-in user', $mail[0]['body'] );
	}

	public function test_at_most_twenty_emails_per_hour_but_every_event_is_logged(): void {
		for ( $i = 1; $i <= 22; $i++ ) {
			do_action( 'activated_plugin', "p{$i}/p{$i}.php", false );
			$this->notifier->flush();
		}

		$this->assertCount( 20, $this->sent_mail() );
		$this->assertCount( 22, $this->alert_rows(), 'throttled events are still in the log' );
		$this->assertSame( 20, (int) get_transient( 'wpb_alert_count' ) );
	}

	public function test_the_throttle_boundary(): void {
		set_transient( 'wpb_alert_count', 19, HOUR_IN_SECONDS );
		do_action( 'activated_plugin', 'a/a.php', false );
		$this->assertCount( 1, $this->flush(), 'the 20th email still goes out' );

		do_action( 'activated_plugin', 'b/b.php', false );
		$this->assertCount( 1, $this->flush(), 'the 21st does not (mail count unchanged)' );
		$this->assertCount( 2, $this->alert_rows() );
	}

	public function test_throttle_resets_when_the_transient_expires(): void {
		set_transient( 'wpb_alert_count', 20, HOUR_IN_SECONDS );
		delete_transient( 'wpb_alert_count' );
		do_action( 'activated_plugin', 'a/a.php', false );

		$this->assertCount( 1, $this->flush() );
	}

	public function test_alerts_switched_off_send_and_log_nothing(): void {
		$this->set_settings( array( 'alerts' => array( 'enabled' => false ) ) );

		self::factory()->user->create( array( 'role' => 'administrator' ) );
		do_action( 'activated_plugin', 'hello.php', false );

		$this->assertCount( 0, $this->flush() );
		$this->assertCount( 0, $this->alert_rows() );
	}

	/* ---------------- recipients ---------------- */

	public function test_recipients_fall_back_to_the_admin_email(): void {
		$this->set_admin_email( 'owner@example.org' );

		$this->assertSame( array( 'owner@example.org' ), $this->notifier->recipients() );
		do_action( 'activated_plugin', 'hello.php', false );
		$mail = $this->flush();
		$this->assertSame( 'owner@example.org', $mail[0]['to'][0][0] );
	}

	public function test_custom_recipients_replace_the_admin_email(): void {
		$this->set_admin_email( 'owner@example.org' );
		$this->set_settings( array( 'alerts' => array( 'recipients' => array( 'ops@example.org', 'sec@example.org' ) ) ) );

		do_action( 'activated_plugin', 'hello.php', false );
		$mail = $this->flush();

		$this->assertCount( 1, $mail );
		$to = array_column( $mail[0]['to'], 0 );
		$this->assertSame( array( 'ops@example.org', 'sec@example.org' ), $to );
	}

	public function test_invalid_recipients_are_dropped_by_settings_and_fall_back(): void {
		$this->set_admin_email( 'owner@example.org' );
		$this->set_settings( array( 'alerts' => array( 'recipients' => array( 'not-an-email', "x@y.z\nBcc: evil@example.com" ) ) ) );

		$recipients = $this->notifier->recipients();

		$this->assertNotContains( 'not-an-email', $recipients );
		foreach ( $recipients as $r ) {
			$this->assertStringNotContainsString( "\n", $r );
		}
	}

	/* ---------------- test email ---------------- */

	public function test_send_test_sends_a_test_alert_and_returns_true(): void {
		$this->set_admin_email( 'owner@example.org' );

		$result = $this->notifier->send_test();

		$this->assertTrue( $result );
		$mail = $this->sent_mail();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'Test alert', $mail[0]['subject'] );
		$this->assertSame( 'owner@example.org', $mail[0]['to'][0][0] );
	}

	public function test_send_test_returns_the_wp_mail_failed_message(): void {
		// An unusable From address makes wp_mail() fail and fire wp_mail_failed.
		add_filter(
			'wp_mail_from',
			static function () {
				return 'not an address';
			}
		);

		$result = $this->notifier->send_test();

		$this->assertIsString( $result );
		$this->assertNotSame( '', $result );
		$this->assertStringContainsString( 'not an address', $result );
		$this->assertCount( 0, $this->sent_mail() );
	}

	public function test_send_test_falls_back_to_a_generic_message_when_mail_fails_silently(): void {
		add_filter( 'pre_wp_mail', '__return_false' );

		$result = $this->notifier->send_test();

		$this->assertIsString( $result );
		$this->assertStringContainsString( 'could not send the email', $result );
	}

	public function test_send_test_ignores_the_throttle_and_does_not_count(): void {
		set_transient( 'wpb_alert_count', 20, HOUR_IN_SECONDS );

		$this->assertTrue( $this->notifier->send_test() );
		$this->assertSame( 20, (int) get_transient( 'wpb_alert_count' ) );
	}

	public function test_send_test_stops_listening_for_failures_afterwards(): void {
		$before = has_action( 'wp_mail_failed' );
		$this->notifier->send_test();

		$this->assertSame( $before, has_action( 'wp_mail_failed' ) );
	}
}
