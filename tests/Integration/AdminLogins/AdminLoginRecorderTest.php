<?php
/**
 * WPB-13: administrator logins recorded in the Activity Log, with the new-location alert.
 *
 * Every "request" below uses a fresh recorder, because the real one remembers per request
 * which users it already recorded. Hook wiring is checked through the real actions.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\AdminLogins;

use WPBouncer\AdminLogins\AdminLoginRecorder;
use WPBouncer\AdminLogins\LoginHistoryRepository;
use WPBouncer\Installer;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Log\BudgetedBlockLog;
use WPBouncer\Plugin;
use WPBouncer\Privacy\AdminLoginPrivacy;
use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Log\WriteBudget;
use WPBouncer\Tests\Support\FakeGeo;
use WPBouncer\Tests\Support\FrozenClock;

/**
 * @covers \WPBouncer\AdminLogins\AdminLoginRecorder
 * @covers \WPBouncer\AdminLogins\LoginHistoryRepository
 * @covers \WPBouncer\Alerts\AlertNotifier::on_admin_login
 * @covers \WPBouncer\Plugin::client_ip_is_reliable
 */
final class AdminLoginRecorderTest extends IntegrationTestCase {

	private const IP_A = '203.0.113.9';
	private const IP_B = '198.51.100.20';

	public function set_up() {
		parent::set_up();
		$this->flush_alerts();
	}

	public function tear_down() {
		if ( class_exists( 'Two_Factor_Core', false ) ) {
			\Two_Factor_Core::$users = array();
		}
		remove_all_filters( 'wp_bouncer_admin_login_defer' );
		remove_all_filters( 'wp_bouncer_admin_login_is_admin' );
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	private function flush_alerts(): void {
		$this->plugin->alerts()->flush();
		$this->clear_mail();
	}

	/** An administrator, with the "new administrator" alert the factory causes already sent. */
	private function admin( string $role = 'administrator' ): \WP_User {
		$id = self::factory()->user->create( array( 'role' => $role ) );
		$this->flush_alerts();
		return get_user_by( 'id', $id );
	}

	private function geo( array $map ): void {
		( new \ReflectionProperty( Plugin::class, 'geo' ) )->setValue( $this->plugin, new FakeGeo( $map ) );
	}

	/** Start a new request from an IP (and optionally a country). */
	private function request( string $ip, ?string $country = 'DE', string $uri = '/wp-login.php' ): void {
		$this->fake_request(
			array(
				'REMOTE_ADDR' => $ip,
				'REQUEST_URI' => $uri,
			)
		);
		$this->geo( null === $country ? array() : array( $ip => $country ) );
	}

	private function recorder(): AdminLoginRecorder {
		return new AdminLoginRecorder( $this->plugin );
	}

	private function login( \WP_User $user, string $ip = self::IP_A, ?string $country = 'DE' ): void {
		$this->request( $ip, $country );
		$this->recorder()->on_wp_login( $user->user_login, $user );
	}

	/** @return array<int, array<string, string>> */
	private function rows( string $rule = 'admin_login' ): array {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}bouncer_log WHERE rule = %s ORDER BY id", $rule ), ARRAY_A ); // phpcs:ignore WordPress.DB
	}

	private function history( \WP_User $user ): mixed {
		return get_user_option( LoginHistoryRepository::META, $user->ID );
	}

	private function mails(): array {
		$this->plugin->alerts()->flush();
		return $this->sent_mail();
	}

	/* ---------------- who is recorded (AC 1, 3) ---------------- */

	public function test_an_admin_login_writes_one_row_with_everything_the_story_asks_for(): void {
		$user = $this->admin();
		$this->login( $user );

		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( BlockLogInterface::ACTION_LOGIN, $rows[0]['action'] );
		$this->assertSame( self::IP_A, $rows[0]['ip'] );
		$this->assertSame( 'DE', $rows[0]['country'] );
		$this->assertStringStartsWith( 'User ID ' . $user->ID . ': ' . $user->user_login . ' — interactive password', $rows[0]['reason'] );
		$this->assertStringContainsString( 'first recorded login', $rows[0]['reason'] );
		$this->assertNotSame( '', $rows[0]['created_at'] );
		$this->assertStringContainsString( 'Mozilla', $rows[0]['user_agent'] );
		$this->assertStringNotContainsString( $user->user_email, $rows[0]['reason'] );
	}

	public function test_country_is_empty_without_a_geo_answer(): void {
		$this->login( $this->admin(), self::IP_A, null );
		$this->assertSame( '', $this->rows()[0]['country'] );
	}

	public function test_a_manage_options_user_who_is_not_an_administrator_is_recorded(): void {
		$user = $this->admin( 'editor' );
		$user->add_cap( 'manage_options' );
		$this->login( get_user_by( 'id', $user->ID ) );
		$this->assertCount( 1, $this->rows() );
	}

	public function test_editors_and_subscribers_are_not_recorded_and_get_no_history(): void {
		foreach ( array( 'editor', 'subscriber', 'author' ) as $role ) {
			$user = $this->admin( $role );
			$this->login( $user );
			$this->assertFalse( $this->history( $user ), $role );
		}
		$this->assertSame( array(), $this->rows() );
		$this->assertSame( array(), $this->mails() );
	}

	public function test_a_promoted_user_is_recorded_at_the_next_login_and_a_demoted_one_is_not(): void {
		$user = $this->admin( 'editor' );
		$this->login( $user );
		$this->assertCount( 0, $this->rows() );

		$user->set_role( 'administrator' );
		$this->flush_alerts();
		$this->login( get_user_by( 'id', $user->ID ) );
		$this->assertCount( 1, $this->rows() );

		$user->set_role( 'subscriber' );
		$this->login( get_user_by( 'id', $user->ID ), self::IP_B );
		$this->assertCount( 1, $this->rows(), 'role at login time decides' );
	}

	public function test_the_scope_filter_can_widen_and_narrow(): void {
		$editor = $this->admin( 'editor' );
		add_filter( 'wp_bouncer_admin_login_is_admin', static fn( $is, $u ) => $is || in_array( 'editor', $u->roles, true ), 10, 2 );
		$this->login( $editor );
		$this->assertCount( 1, $this->rows() );
		remove_all_filters( 'wp_bouncer_admin_login_is_admin' );

		add_filter( 'wp_bouncer_admin_login_is_admin', '__return_false' );
		$this->login( $this->admin() );
		remove_all_filters( 'wp_bouncer_admin_login_is_admin' );
		$this->assertCount( 1, $this->rows() );
	}

	public function test_the_real_wp_login_action_is_wired_and_a_user_is_recorded_once_per_request(): void {
		$user = $this->admin();
		$this->request( self::IP_A );
		do_action( 'wp_login', $user->user_login, $user );
		do_action( 'wp_login', $user->user_login, $user );
		$this->assertCount( 1, $this->rows() );
	}

	public function test_wp_signon_by_an_admin_writes_a_row(): void {
		$user = $this->admin();
		wp_set_password( 'correct horse battery', $user->ID );
		add_filter( 'send_auth_cookies', '__return_false' );
		$this->request( self::IP_A );
		$result = wp_signon( array( 'user_login' => $user->user_login, 'user_password' => 'correct horse battery' ) );
		$this->assertInstanceOf( \WP_User::class, $result );
		$this->assertCount( 1, $this->rows() );
	}

	public function test_a_wrong_password_writes_nothing(): void {
		$user = $this->admin();
		wp_set_password( 'correct horse battery', $user->ID );
		add_filter( 'send_auth_cookies', '__return_false' );
		$this->request( self::IP_A );
		$result = wp_signon( array( 'user_login' => $user->user_login, 'user_password' => 'nope' ) );
		$this->assertWPError( $result );
		$this->assertSame( array(), $this->rows() );
	}

	/* ---------------- history and alerts (AC 7 to 9) ---------------- */

	public function test_first_login_is_silent_and_starts_the_history(): void {
		$user = $this->admin();
		$this->login( $user );
		$this->assertSame( array(), $this->mails() );
		$h = $this->history( $user );
		$this->assertSame( '203.0.113.0/24', $h['e'][0]['r'] );
		$this->assertSame( 'DE', $h['e'][0]['c'] );
		$this->assertSame( array(), $this->alert_rows() );
	}

	/** Alert rows about a login (the factory's own "new administrator" rows are not counted). */
	private function alert_rows(): array {
		return array_values( array_filter( $this->rows( 'alerts' ), static fn( $r ) => str_contains( $r['reason'], 'login' ) ) );
	}

	public function test_a_new_range_sends_one_mail_and_the_same_range_again_none(): void {
		$user = $this->admin();
		$this->login( $user );
		$this->login( $user, '203.0.113.200' );
		$this->assertSame( array(), $this->mails(), 'same /24' );

		$this->login( $user, self::IP_B, 'DE' );
		$mail = $this->mails();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'Administrator login from a new location', $mail[0]['subject'] );
		$this->assertStringContainsString( 'User: ' . $user->user_login . ' (user ID ' . $user->ID . ')', $mail[0]['body'] );
		$this->assertStringContainsString( 'Method: interactive password', $mail[0]['body'] );
		$this->assertStringContainsString( 'IP range 198.51.100.0/24', $mail[0]['body'] );
		$this->assertStringContainsString( self::IP_B, $mail[0]['body'] );
		$this->assertStringContainsString( 'If this was you, there is nothing to do', $mail[0]['body'] );
		$this->assertStringNotContainsString( $user->user_email, $mail[0]['body'] );
		$this->assertStringNotContainsString( $user->user_pass, $mail[0]['body'] );

		$this->clear_mail();
		$this->login( $user, '198.51.100.99' );
		$this->assertSame( array(), $this->mails(), 'the new range is now known' );

		$rows = $this->rows();
		$this->assertStringContainsString( 'new location: IP range 198.51.100.0/24, country DE', $rows[2]['reason'] );
		$this->assertSame( array(), $this->alert_rows(), 'the login row is the record, no second row' );
	}

	public function test_a_new_country_alerts(): void {
		$user = $this->admin();
		$this->login( $user, self::IP_A, 'DE' );
		$this->login( $user, self::IP_A, 'FR' );
		$mail = $this->mails();
		$this->assertCount( 1, $mail );
		$this->assertStringContainsString( 'country FR', $mail[0]['body'] );
	}

	public function test_no_geo_data_compares_the_range_only(): void {
		$user = $this->admin();
		$this->login( $user, self::IP_A, null );
		$this->login( $user, '203.0.113.50', null );
		$this->assertSame( array(), $this->mails() );
		$this->login( $user, self::IP_B, null );
		$this->assertCount( 1, $this->mails() );
	}

	public function test_a_dormant_account_alerts_after_the_window(): void {
		$user = $this->admin();
		$this->login( $user );
		$h = $this->history( $user );
		foreach ( $h['e'] as $i => $e ) {
			$h['e'][ $i ]['t'] = time() - 91 * DAY_IN_SECONDS;
		}
		update_user_option( $user->ID, LoginHistoryRepository::META, $h );
		$this->login( $user );
		$this->assertCount( 1, $this->mails(), 'an old history is not a first login' );
	}

	public function test_junk_history_meta_counts_as_never_recorded(): void {
		$user = $this->admin();
		update_user_option( $user->ID, LoginHistoryRepository::META, 'garbage' );
		$this->login( $user );
		$this->assertSame( array(), $this->mails() );
		$this->assertIsArray( $this->history( $user ) );
	}

	public function test_the_alert_setting_off_still_records_rows_and_history(): void {
		$this->set_settings( array( 'alerts' => array( 'admin_login_location' => false ) ) );
		$user = $this->admin();
		$this->login( $user );
		$this->login( $user, self::IP_B );
		$this->assertCount( 2, $this->rows() );
		$this->assertSame( array(), $this->mails() );
		$this->assertCount( 2, $this->history( $user )['e'] );
	}

	public function test_alerts_master_switch_off_sends_no_mail_but_records(): void {
		$this->set_settings( array( 'alerts' => array( 'enabled' => false ) ) );
		$user = $this->admin();
		$this->login( $user );
		$this->login( $user, self::IP_B );
		$this->assertCount( 2, $this->rows() );
		$this->assertSame( array(), $this->mails() );
	}

	public function test_recording_off_writes_no_row_no_history_and_no_mail(): void {
		$this->set_settings( array( 'alerts' => array( 'record_admin_logins' => false ) ) );
		$user = $this->admin();
		$this->login( $user );
		$this->login( $user, self::IP_B );
		$this->assertSame( array(), $this->rows() );
		$this->assertFalse( $this->history( $user ) );
		$this->assertSame( array(), $this->mails() );
	}

	public function test_the_alert_filter_can_suppress_one_mail(): void {
		$user = $this->admin();
		$this->login( $user );
		add_filter( 'wp_bouncer_admin_login_alert', '__return_false' );
		$this->login( $user, self::IP_B );
		remove_all_filters( 'wp_bouncer_admin_login_alert' );
		$this->assertSame( array(), $this->mails() );
		$this->assertCount( 2, $this->rows() );
	}

	public function test_recorded_action_gets_the_event_and_flags(): void {
		$seen = array();
		add_action(
			'wp_bouncer_admin_login_recorded',
			static function ( $event, $flags ) use ( &$seen ) {
				$seen[] = array( $event, $flags );
			},
			10,
			2
		);
		$user = $this->admin();
		$this->login( $user );
		$this->login( $user, self::IP_B );
		$this->assertTrue( $seen[0][1]['first'] );
		$this->assertTrue( $seen[1][1]['new_range'] );
		$this->assertTrue( $seen[1][1]['reliable'] );
		$this->assertSame( $user->ID, $seen[1][0]['user_id'] );
		$this->assertSame( '198.51.100.0/24', $seen[1][0]['range'] );
	}

	/* ---------------- alert throttling (SB13-07) ---------------- */

	public function test_at_most_3_alerts_per_user_per_hour_and_the_fourth_is_counted_in_a_throttle_notice(): void {
		$user = $this->admin();
		$this->login( $user );
		for ( $i = 1; $i <= 4; $i++ ) {
			$this->login( $user, '10.9.' . $i . '.5', 'DE' );
			$this->plugin->alerts()->flush();
		}
		$mail    = $this->sent_mail();
		$alerts  = array_filter( $mail, static fn( $m ) => str_contains( (string) $m['subject'], 'Administrator login from a new location' ) );
		$notices = array_filter( $mail, static fn( $m ) => str_contains( (string) $m['subject'], 'Admin login alerts throttled' ) );
		$this->assertCount( 3, $alerts );
		$this->assertCount( 1, $notices, 'the capped alert is not silent' );
		$this->assertStringContainsString( '1 not emailed', array_values( $notices )[0]['body'] );
		$rows = $this->rows();
		$this->assertCount( 5, $rows, 'every login is still a row' );
		$this->assertStringNotContainsString( 'alert throttled', $rows[3]['reason'] );
		$this->assertStringContainsString( 'alert throttled', $rows[4]['reason'] );
	}

	public function test_at_most_10_login_mails_per_site_then_one_throttle_notice(): void {
		$users = array();
		for ( $i = 0; $i < 4; $i++ ) {
			$users[] = $this->admin();
		}
		foreach ( $users as $user ) {
			$this->login( $user, '10.8.0.5' );
		}
		$n = 0;
		for ( $r = 1; $r <= 3; $r++ ) {
			foreach ( $users as $user ) {
				$this->login( $user, '10.8.' . $r . '.5' );
				$this->plugin->alerts()->flush();
				++$n;
			}
		}
		$mail    = $this->sent_mail();
		$notices = array_filter( $mail, static fn( $m ) => str_contains( (string) $m['subject'], 'Admin login alerts throttled' ) );
		$alerts  = array_filter( $mail, static fn( $m ) => str_contains( (string) $m['subject'], 'Administrator login from a new location' ) );
		$this->assertSame( 12, $n );
		$this->assertCount( 10, $alerts );
		$this->assertCount( 1, $notices, 'one notice, not one per dropped mail' );
		$this->assertStringContainsString( '1 not emailed', array_values( $notices )[0]['body'] );
	}

	public function test_login_mail_does_not_use_the_general_or_critical_budget(): void {
		set_transient( 'wpb_alert_count', 20, HOUR_IN_SECONDS );
		set_transient( 'wpb_alert_count_critical', 20, HOUR_IN_SECONDS );
		$user = $this->admin();
		$this->login( $user );
		$this->login( $user, self::IP_B );
		$this->assertCount( 1, $this->mails() );
	}

	/* ---------------- IP reliability (SB13-02) ---------------- */

	public function test_a_forged_forwarded_header_with_remote_addr_changes_nothing(): void {
		$user = $this->admin();
		$this->fake_request(
			array(
				'REMOTE_ADDR'          => self::IP_A,
				'HTTP_X_FORWARDED_FOR' => '8.8.8.8',
				'HTTP_X_REAL_IP'       => '8.8.8.8',
			)
		);
		$this->geo( array( self::IP_A => 'DE' ) );
		$this->recorder()->on_wp_login( $user->user_login, $user );
		$this->assertSame( self::IP_A, $this->rows()[0]['ip'] );
		$this->assertSame( '203.0.113.0/24', $this->history( $user )['e'][0]['r'] );
	}

	public function test_a_loopback_client_is_recorded_as_not_checked_with_no_history_and_no_mail(): void {
		$user = $this->admin();
		$this->login( $user, '127.0.0.1', null );
		$this->login( $user, '127.0.0.1', null );
		$rows = $this->rows();
		$this->assertCount( 2, $rows );
		$this->assertStringContainsString( 'location not checked: client IP not reliable', $rows[0]['reason'] );
		$this->assertFalse( $this->history( $user ) );
		$this->assertSame( array(), $this->mails() );
	}

	public function test_a_header_ip_source_with_no_trusted_proxy_is_not_reliable(): void {
		$this->set_settings( array( 'ip_source' => 'x_forwarded_for' ) );
		$user = $this->admin();
		$this->fake_request(
			array(
				'REMOTE_ADDR'          => '10.0.0.5',
				'HTTP_X_FORWARDED_FOR' => '198.51.100.7',
			)
		);
		$this->recorder()->on_wp_login( $user->user_login, $user );
		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'not reliable', $rows[0]['reason'] );
		$this->assertFalse( $this->history( $user ) );
		$this->assertSame( array(), $this->mails() );
		$this->assertFalse( $this->plugin->client_ip_is_reliable() );
	}

	public function test_a_normal_public_client_is_reliable(): void {
		$this->request( self::IP_A );
		$this->assertTrue( $this->plugin->client_ip_is_reliable() );
	}

	/* ---------------- application passwords and XML-RPC (AC 2, SB13-08) ---------------- */

	public function test_the_app_password_path_never_asks_who_the_current_user_is(): void {
		$user = $this->admin();
		$this->request( self::IP_A, 'DE', '/wp-json/wp/v2/posts' );
		$calls = 0;
		$GLOBALS['current_user'] = null; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$spy = static function ( $id ) use ( &$calls ) {
			++$calls;
			return $id;
		};
		add_filter( 'determine_current_user', $spy, 1 );
		$this->recorder()->on_application_password( $user, array( 'name' => 'secret app name', 'uuid' => 'x' ) );
		$this->assertSame( 0, $calls, 'wp_get_current_user() or current_user_can() was called' );
		$this->assertCount( 1, $this->rows() );

		wp_get_current_user(); // Control: the spy does see a lookup.
		$this->assertSame( 1, $calls );
		remove_filter( 'determine_current_user', $spy, 1 );
	}

	public function test_an_app_password_login_over_rest_has_its_own_label_and_never_stores_the_name(): void {
		$user = $this->admin();
		$this->request( self::IP_A, 'DE', '/wp-json/wp/v2/posts' );
		$this->recorder()->on_application_password( $user, array( 'name' => 'secret app name', 'uuid' => 'u-1' ) );
		$row = $this->rows()[0];
		$this->assertStringContainsString( ' — application password (REST)', $row['reason'] );
		$this->assertStringNotContainsString( 'secret app name', $row['reason'] );
		$this->assertStringNotContainsString( 'u-1', $row['reason'] );
	}

	public function test_an_app_password_login_over_xmlrpc_is_labelled_by_transport(): void {
		$user = $this->admin();
		$this->request( self::IP_A, 'DE', '/xmlrpc.php' );
		$this->recorder()->on_application_password( $user, array() );
		$this->assertStringContainsString( ' — application password (XML-RPC)', $this->rows()[0]['reason'] );
	}

	public function test_the_real_app_password_hook_records_through_core(): void {
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		add_filter( 'application_password_is_api_request', '__return_true' );
		$user = $this->admin();
		$created = \WP_Application_Passwords::create_new_application_password( $user->ID, array( 'name' => 'ci' ) );
		$this->request( self::IP_A, 'DE', '/wp-json/wp/v2/posts' );
		$result = wp_authenticate_application_password( null, $user->user_login, $created[0] );
		$this->assertInstanceOf( \WP_User::class, $result );
		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( 'application password (REST)', $rows[0]['reason'] );
		$this->assertStringNotContainsString( $created[0], $rows[0]['reason'] );
	}

	public function test_a_non_admin_app_password_login_writes_nothing(): void {
		$user = $this->admin( 'editor' );
		$this->request( self::IP_A, 'DE', '/wp-json/wp/v2/posts' );
		$this->recorder()->on_application_password( $user, array() );
		$this->assertSame( array(), $this->rows() );
	}

	public function test_app_password_logins_are_deduplicated_per_hour_with_one_geo_and_history_read(): void {
		$user  = $this->admin();
		$reads = 0;
		add_filter(
			'get_user_metadata',
			static function ( $value, $object_id, $meta_key ) use ( &$reads ) {
				if ( str_ends_with( (string) $meta_key, LoginHistoryRepository::META ) ) {
					++$reads;
				}
				return $value;
			},
			10,
			3
		);
		$this->request( self::IP_A, 'DE', '/wp-json/wp/v2/posts' );
		$geo = new FakeGeo( array( self::IP_A => 'DE' ) );
		( new \ReflectionProperty( Plugin::class, 'geo' ) )->setValue( $this->plugin, $geo );
		for ( $i = 0; $i < 200; $i++ ) {
			$this->recorder()->on_application_password( $user, array() );
		}
		$this->assertCount( 1, $this->rows() );
		$this->assertSame( 1, $geo->lookups, 'later calls stop at the one store read' );
		$this->assertLessThanOrEqual( 3, $reads, 'history reads do not grow with the calls' );
	}

	public function test_the_dedupe_window_is_per_user_range_and_method(): void {
		$user  = $this->admin();
		$other = $this->admin();
		$this->request( self::IP_A, 'DE', '/wp-json/wp/v2/posts' );
		$this->recorder()->on_application_password( $user, array() );
		$this->recorder()->on_application_password( $other, array() );
		$this->assertCount( 2, $this->rows(), 'another user' );

		$this->request( self::IP_B, 'DE', '/wp-json/wp/v2/posts' );
		$this->recorder()->on_application_password( $user, array() );
		$this->assertCount( 3, $this->rows(), 'a new range writes immediately' );
		$this->assertCount( 1, $this->mails(), 'and is assessed for the alert' );

		$this->request( self::IP_A, 'DE', '/xmlrpc.php' );
		$this->recorder()->on_application_password( $user, array() );
		$this->assertCount( 4, $this->rows(), 'another method' );
	}

	public function test_an_interactive_login_is_never_deduplicated(): void {
		$user = $this->admin();
		$this->login( $user );
		$this->login( $user );
		$this->assertCount( 2, $this->rows() );
	}

	public function test_a_new_dedupe_window_after_an_hour_writes_again(): void {
		$user = $this->admin();
		$this->request( self::IP_A, 'DE', '/wp-json/wp/v2/posts' );
		$this->recorder()->on_application_password( $user, array() );
		$this->recorder()->on_application_password( $user, array() );
		$this->assertCount( 1, $this->rows() );
		$key = 'login_seen:' . $user->ID . '|203.0.113.0/24|application password (REST)';
		$this->plugin->store()->delete( $key );
		// A network keeps the key in a site transient, with the site-set scope appended.
		$scope = ( new \ReflectionMethod( AdminLoginRecorder::class, 'dedupe_scope' ) )->invoke( $this->recorder(), $user->ID, get_current_blog_id() );
		delete_site_transient( 'wpb_' . md5( $key . $scope ) );
		$this->recorder()->on_application_password( $user, array() );
		$this->assertCount( 2, $this->rows() );
	}

	public function test_the_dedupe_key_keeps_no_raw_ip_in_the_database(): void {
		global $wpdb;
		$user = $this->admin();
		$this->request( self::IP_A, 'DE', '/wp-json/wp/v2/posts' );
		$this->recorder()->on_application_password( $user, array() );
		$hits = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s AND option_name LIKE %s", '%transient%', '%203.0.113%' ) ); // phpcs:ignore WordPress.DB
		$this->assertSame( '0', (string) $hits );
	}

	public function test_an_xmlrpc_password_login_is_recorded_once_at_the_first_call(): void {
		$user = $this->admin();
		$this->request( self::IP_A, 'DE', '/xmlrpc.php' );
		$rec = $this->recorder();
		$this->assertSame( $user, $rec->note_xmlrpc_authentication( $user ), 'the filter returns its value unchanged' );
		$err = new \WP_Error( 'x' );
		$this->assertSame( $err, $rec->note_xmlrpc_authentication( $err ) );
		wp_set_current_user( $user->ID );
		$rec->on_xmlrpc_call();
		$rec->on_xmlrpc_call();
		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertStringContainsString( ' — password (XML-RPC)', $rows[0]['reason'] );
	}

	public function test_an_xmlrpc_call_without_a_password_login_records_nothing(): void {
		$user = $this->admin();
		$this->request( self::IP_A, 'DE', '/xmlrpc.php' );
		wp_set_current_user( $user->ID );
		$this->recorder()->on_xmlrpc_call();
		$this->assertSame( array(), $this->rows() );
	}

	public function test_an_xmlrpc_app_password_call_is_not_recorded_twice(): void {
		$user = $this->admin();
		$this->request( self::IP_A, 'DE', '/xmlrpc.php' );
		$rec = $this->recorder();
		$rec->on_application_password( $user, array() );
		$rec->note_xmlrpc_authentication( $user );
		wp_set_current_user( $user->ID );
		$rec->on_xmlrpc_call();
		$this->assertCount( 1, $this->rows() );
	}

	/** RT-16: the second XML-RPC app-password call within the hour hits the dedupe cache and still adds no row. */
	public function test_a_deduped_xmlrpc_app_password_call_adds_no_password_row(): void {
		$user = $this->admin();
		$this->request( self::IP_A, 'DE', '/xmlrpc.php' );
		foreach ( array( 1, 2 ) as $call ) {
			$rec = $this->recorder();
			$rec->on_application_password( $user, array() );
			$rec->note_xmlrpc_authentication( $user );
			wp_set_current_user( $user->ID );
			$rec->on_xmlrpc_call();
			$this->assertCount( 1, $this->rows(), "call $call" );
		}
	}

	public function test_the_xmlrpc_hooks_are_not_registered_outside_xmlrpc(): void {
		$rec = $this->recorder();
		$rec->register();
		$this->assertFalse( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST );
		$this->assertFalse( has_filter( 'authenticate', array( $rec, 'note_xmlrpc_authentication' ) ) );
		$this->assertFalse( has_action( 'xmlrpc_call', array( $rec, 'on_xmlrpc_call' ) ) );
		$this->assertSame( 20, has_action( 'wp_login', array( $rec, 'on_wp_login' ) ) );
		$this->assertSame( 20, has_action( 'application_password_did_authenticate', array( $rec, 'on_application_password' ) ) );
		$this->assertSame( 20, has_action( 'two_factor_user_authenticated', array( $rec, 'on_second_factor' ) ) );
		$this->assertSame( 10, has_action( 'wp_bouncer_record_admin_login', array( $rec, 'on_second_factor' ) ) );
	}

	public function test_the_second_factor_hook_records_with_its_own_label(): void {
		$user = $this->admin();
		$this->request( self::IP_A );
		do_action( 'wp_bouncer_record_admin_login', $user );
		$this->assertStringContainsString( ' — interactive password + two-factor', $this->rows()[0]['reason'] );
	}

	public function test_registering_adds_no_work_on_other_requests(): void {
		global $wpdb;
		$before = $wpdb->num_queries;
		$rec    = $this->recorder();
		$rec->register();
		$this->assertSame( $before, $wpdb->num_queries, 'register() runs no query' );
	}

	/* ---------------- a failure must never break the login (AC 11) ---------------- */

	public function test_a_throwing_log_does_not_break_wp_signon(): void {
		$user = $this->admin();
		wp_set_password( 'correct horse battery', $user->ID );
		add_filter( 'send_auth_cookies', '__return_false' );
		$thrower = new class() implements BlockLogInterface {
			public function record( array $entry ): int {
				throw new \RuntimeException( 'database is gone' );
			}
		};
		$prop = new \ReflectionProperty( Plugin::class, 'log_writer' );
		$old  = $prop->getValue( $this->plugin );
		$prop->setValue( $this->plugin, new BudgetedBlockLog( $thrower, $this->plugin->write_budget() ) );
		$this->request( self::IP_A );
		try {
			$result = wp_signon( array( 'user_login' => $user->user_login, 'user_password' => 'correct horse battery' ) );
		} finally {
			$prop->setValue( $this->plugin, $old );
		}
		$this->assertInstanceOf( \WP_User::class, $result );
		$this->assertFalse( $this->history( $user ), 'no history is saved for an unwritten row' );
	}

	public function test_a_throwing_listener_does_not_break_wp_signon(): void {
		$user = $this->admin();
		wp_set_password( 'correct horse battery', $user->ID );
		add_filter( 'send_auth_cookies', '__return_false' );
		add_action(
			'wp_bouncer_admin_login_recorded',
			static function () {
				throw new \RuntimeException( 'listener bug' );
			}
		);
		$this->request( self::IP_A );
		$result = wp_signon( array( 'user_login' => $user->user_login, 'user_password' => 'correct horse battery' ) );
		$this->assertInstanceOf( \WP_User::class, $result );
		$this->assertCount( 1, $this->rows() );
	}

	public function test_a_failing_notifier_does_not_break_the_login(): void {
		$user = $this->admin();
		$this->login( $user );
		add_filter(
			'wp_bouncer_admin_login_alert',
			static function () {
				throw new \RuntimeException( 'filter bug' );
			}
		);
		$this->login( $user, self::IP_B );
		remove_all_filters( 'wp_bouncer_admin_login_alert' );
		$this->assertCount( 2, $this->rows() );
	}

	public function test_a_throwing_scope_filter_does_not_break_the_login(): void {
		$user = $this->admin();
		add_filter(
			'wp_bouncer_admin_login_is_admin',
			static function () {
				throw new \RuntimeException( 'scope bug' );
			}
		);
		$this->login( $user );
		remove_all_filters( 'wp_bouncer_admin_login_is_admin' );
		$this->assertSame( array(), $this->rows() );
	}

	public function test_a_non_user_argument_is_ignored(): void {
		$rec = $this->recorder();
		$rec->on_wp_login( 'x', null );
		$rec->on_application_password( null );
		$rec->on_application_password( false );
		$rec->on_second_factor( 'nobody' );
		$this->assertSame( array(), $this->rows() );
	}

	/* ---------------- budget (SB13-09) ---------------- */

	public function test_login_rows_over_the_budget_are_counted_in_the_suppressed_summary(): void {
		$clock  = new FrozenClock( 1900000000 );
		$budget = new WriteBudget( $this->plugin->store(), $clock, 500, 30, 5 );
		$prop   = new \ReflectionProperty( Plugin::class, 'log_writer' );
		$old    = $prop->getValue( $this->plugin );
		$prop->setValue( $this->plugin, new BudgetedBlockLog( $this->plugin->log(), $budget ) );
		try {
			$users = array();
			for ( $i = 0; $i < 8; $i++ ) {
				$users[] = $this->admin();
			}
			foreach ( $users as $user ) {
				$this->login( $user );
			}
			$this->assertCount( 5, $this->rows(), 'the login lane holds 5 a minute' );

			$clock->advance( 60 );
			$this->login( $this->admin() );
		} finally {
			$prop->setValue( $this->plugin, $old );
		}
		$summary = $this->rows( 'wp_bouncer' );
		$this->assertCount( 1, $summary );
		$this->assertSame( BlockLogInterface::ACTION_SUPPRESSED, $summary[0]['action'] );
		$this->assertStringContainsString( '3 further events suppressed', $summary[0]['reason'] );
		$this->assertStringContainsString( 'admin_login 3', $summary[0]['reason'] );
		$this->assertCount( 6, $this->rows(), 'the next minute writes again' );
	}

	/* ---------------- multisite (AC 4) ---------------- */

	public function test_a_super_admin_login_is_written_to_the_log_of_the_site_it_happened_on(): void {
		global $wpdb;
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		$this->use_real_ddl();
		$site = self::factory()->blog->create();
		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		grant_super_admin( $user );
		$user = get_user_by( 'id', $user );
		$this->flush_alerts();

		switch_to_blog( $site );
		Installer::activate();
		$log_writer = new \ReflectionProperty( Plugin::class, 'log_writer' );
		$log        = new \ReflectionProperty( Plugin::class, 'log' );
		$old        = array( $log->getValue( $this->plugin ), $log_writer->getValue( $this->plugin ) );
		$log->setValue( $this->plugin, null );
		$log_writer->setValue( $this->plugin, null );
		try {
			$this->request( self::IP_A );
			$this->recorder()->on_wp_login( $user->user_login, $user );
			$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}bouncer_log WHERE rule = 'admin_login'", ARRAY_A ); // phpcs:ignore WordPress.DB
			$this->assertSame( $wpdb->get_blog_prefix( $site ), $wpdb->prefix );
			$this->assertCount( 1, $rows );
			$this->assertIsArray( get_user_meta( $user->ID, $wpdb->prefix . 'wpb_login_seen', true ), 'per-site history key' );
		} finally {
			$log->setValue( $this->plugin, $old[0] );
			$log_writer->setValue( $this->plugin, $old[1] );
			restore_current_blog();
		}
		$this->assertSame( '', get_user_meta( $user->ID, $wpdb->prefix . 'wpb_login_seen', true ), 'not on the main site' );
		$this->assertSame( array(), $this->rows(), 'not in the main site log' );
	}

	public function test_a_single_site_uses_the_wp_prefixed_history_key(): void {
		if ( is_multisite() ) {
			$this->markTestSkipped( 'Single site only.' );
		}
		$user = $this->admin();
		$this->login( $user );
		$this->assertIsArray( get_user_meta( $user->ID, $GLOBALS['wpdb']->get_blog_prefix() . 'wpb_login_seen', true ) );
	}

	/* ---------------- review fixes (RT-01 to RT-07, CR-2, CR-5) ---------------- */

	public function test_erasing_the_history_does_not_make_the_next_new_range_login_silent(): void {
		$user = $this->admin();
		$this->login( $user );
		( new AdminLoginPrivacy( null, $this->plugin ) )->erase( $user->user_email, 1 );

		$audit = array_values( array_filter( $this->rows( 'alerts' ), static fn( $r ) => str_contains( $r['reason'], 'login data erased' ) ) );
		$this->assertCount( 1, $audit, 'erasing admin-login data leaves an Activity Log row' );
		$this->assertSame( BlockLogInterface::ACTION_ALERT, $audit[0]['action'] );
		$this->assertStringContainsString( 'Administrator login data erased for user ID ' . $user->ID, $audit[0]['reason'] );
		$this->assertSame( array(), $this->history( $user )['e'], 'a tombstone, not "never recorded"' );

		$this->login( $user, self::IP_B, 'FR' );
		$this->assertCount( 1, $this->mails(), 'the first login after an erase from a new range alerts' );
	}

	public function test_a_filter_that_asks_who_the_current_user_is_cannot_loop_the_application_password_login(): void {
		$user = $this->admin();
		$pass = \WP_Application_Passwords::create_new_application_password( $user->ID, array( 'name' => 'test' ) );
		add_filter( 'application_password_is_api_request', '__return_true' );
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		add_filter( 'wp_is_application_passwords_available_for_user', '__return_true' );
		$calls = 0;
		add_filter(
			'wp_bouncer_admin_login_is_admin',
			static function ( $is ) use ( &$calls ) {
				++$calls;
				current_user_can( 'manage_options' ); // Runs determine_current_user again, inside the auth.
				return $is;
			}
		);
		$this->request( self::IP_A, 'DE', '/wp-json/wp/v2/users/me' );
		$_SERVER['PHP_AUTH_USER'] = $user->user_login;
		$_SERVER['PHP_AUTH_PW']   = $pass[0];
		unset( $GLOBALS['current_user'] );
		try {
			$id = wp_validate_application_password( false );
		} finally {
			unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] );
			remove_all_filters( 'application_password_is_api_request' );
			remove_all_filters( 'wp_is_application_passwords_available' );
			remove_all_filters( 'wp_is_application_passwords_available_for_user' );
		}
		$this->assertSame( $user->ID, (int) $id, 'the request still authenticates' );
		$this->assertCount( 1, $this->rows() );
		$this->assertGreaterThanOrEqual( 1, $calls );
	}

	public function test_an_exhausted_login_lane_still_writes_the_alert_row(): void {
		$clock  = new FrozenClock( 1900000000 );
		$budget = new WriteBudget( $this->plugin->store(), $clock, 500, 30, 5 );
		$prop   = new \ReflectionProperty( Plugin::class, 'log_writer' );
		$old    = $prop->getValue( $this->plugin );
		$prop->setValue( $this->plugin, new BudgetedBlockLog( $this->plugin->log(), $budget ) );
		try {
			$user = $this->admin();
			$this->login( $user );
			for ( $i = 0; $i < 4; $i++ ) {
				$this->login( $this->admin() );
			}
			$this->assertCount( 5, $this->rows(), 'the login lane is full' );
			$this->login( $user, self::IP_B, 'FR' );
			$this->assertCount( 5, $this->rows(), 'the login row was dropped' );
			$this->assertCount( 1, $this->mails() );
			$alerts = array_filter( $this->rows( 'alerts' ), static fn( $r ) => str_contains( $r['reason'], 'Administrator login from a new location' ) );
			$this->assertCount( 1, $alerts, 'the alert row is the record when the login row is not' );
		} finally {
			$prop->setValue( $this->plugin, $old );
		}
	}

	public function test_a_user_using_two_factor_is_recorded_only_when_the_second_factor_passes(): void {
		require_once dirname( __DIR__, 2 ) . '/Support/Two_Factor_Core.php';
		$user                      = $this->admin();
		\Two_Factor_Core::$users[] = $user->ID;
		// A 2FA handler that would run after ours (the real one runs at 10 and exits): the password step is incomplete.
		add_action( 'wp_login', array( 'Two_Factor_Core', 'wp_login' ), 30, 2 );
		$this->login( $user );
		remove_action( 'wp_login', array( 'Two_Factor_Core', 'wp_login' ), 30 );
		$this->assertSame( array(), $this->rows(), 'password step only: nothing recorded' );
		$this->assertFalse( $this->history( $user ), 'and no history saved' );

		$this->request( self::IP_A );
		$this->recorder()->on_second_factor( $user );
		$this->assertCount( 1, $this->rows() );
		$this->assertStringContainsString( ' — interactive password + two-factor', $this->rows()[0]['reason'] );
		$this->assertIsArray( $this->history( $user ) );
	}

	/** RT-09: the real Two Factor exits at priority 10, so reaching priority 20 means no challenge happened (SSO, magic link). */
	public function test_a_two_factor_user_whose_login_reaches_priority_20_is_recorded(): void {
		require_once dirname( __DIR__, 2 ) . '/Support/Two_Factor_Core.php';
		$user                      = $this->admin();
		\Two_Factor_Core::$users[] = $user->ID;
		add_action( 'wp_login', array( 'Two_Factor_Core', 'wp_login' ), 10, 2 );
		try {
			$this->login( $user );
		} finally {
			remove_action( 'wp_login', array( 'Two_Factor_Core', 'wp_login' ), 10 );
		}
		$this->assertCount( 1, $this->rows() );
		$this->assertStringContainsString( 'interactive password', $this->rows()[0]['reason'] );
	}

	/** CR2-4: a throwing alert filter must not swallow the alert. */
	public function test_a_failing_alert_decision_fails_open_and_still_mails(): void {
		$user = $this->admin();
		$this->login( $user );
		$this->flush_alerts();
		add_filter(
			'wp_bouncer_admin_login_alert',
			static function () {
				throw new \RuntimeException( 'filter failed' );
			}
		);
		$this->login( $user, self::IP_B, 'FR' );
		remove_all_filters( 'wp_bouncer_admin_login_alert' );
		$this->assertCount( 2, $this->rows() );
		$this->assertCount( 1, $this->mails(), 'fail open: the alert is sent' );
	}

	public function test_a_user_without_two_factor_is_recorded_at_the_password_step(): void {
		require_once dirname( __DIR__, 2 ) . '/Support/Two_Factor_Core.php';
		$this->login( $this->admin() );
		$this->assertCount( 1, $this->rows() );
	}

	public function test_another_two_factor_plugin_can_defer_through_the_filter(): void {
		add_filter( 'wp_bouncer_admin_login_defer', '__return_true' );
		$user = $this->admin();
		$this->login( $user );
		$this->assertSame( array(), $this->rows() );
		$this->assertFalse( $this->history( $user ) );

		$this->request( self::IP_A );
		$this->recorder()->on_wp_login( $user->user_login, $user );
		$this->assertSame( array(), $this->rows(), 'still deferred' );
		do_action( 'wp_bouncer_record_admin_login', $user );
		$this->assertCount( 1, $this->rows() );
	}

	public function test_deleting_a_user_or_removing_them_from_a_site_drops_their_history(): void {
		global $wpdb;
		$user = $this->admin();
		$this->login( $user );
		$this->assertIsArray( $this->history( $user ) );
		$this->recorder()->on_user_deleted( $user->ID );
		if ( is_multisite() ) {
			// RT-12: on a network a delete on one site leaves a tombstone, so a re-added account alerts.
			$this->assertSame( array(), $this->history( $user )['e'] );
		} else {
			$this->assertFalse( $this->history( $user ) );
		}

		$this->login( $user );
		$key = $wpdb->get_blog_prefix( get_current_blog_id() ) . LoginHistoryRepository::META;
		$this->assertIsArray( get_user_meta( $user->ID, $key, true ) );
		$this->recorder()->on_user_removed_from_site( $user->ID, get_current_blog_id() );
		if ( is_multisite() ) {
			$this->assertSame( array(), get_user_meta( $user->ID, $key, true )['e'], 'tombstone on a network' );
		} else {
			$this->assertSame( '', get_user_meta( $user->ID, $key, true ) );
		}
		$this->assertSame( 10, has_action( 'delete_user', array( $this->recorder_registered(), 'on_user_deleted' ) ) );
	}

	/** Register a recorder and return it, to look at its hooks. */
	private function recorder_registered(): AdminLoginRecorder {
		$rec = $this->recorder();
		$rec->register();
		return $rec;
	}

	public function test_an_administrator_of_another_site_is_recorded_and_alerted_on_that_site(): void {
		global $wpdb;
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		$this->use_real_ddl();
		$site = self::factory()->blog->create();
		update_blog_option( $site, 'admin_email', 'owner2@example.org' );
		update_blog_option( $site, 'active_plugins', array( plugin_basename( $this->plugin->file() ) ) );
		update_blog_option( $site, \WPBouncer\Settings::OPTION, \WPBouncer\Settings::defaults() );
		$user = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		add_user_to_blog( $site, $user, 'administrator' );
		$user = get_user_by( 'id', $user );
		$this->flush_alerts();

		switch_to_blog( $site );
		Installer::activate();
		( new LoginHistoryRepository() )->save(
			$user->ID,
			\WPBouncer\AdminLogins\LocationHistory::from_meta(
				array(
					'since' => time() - 1000,
					'e'     => array(
						array(
							'r' => '203.0.113.0/24',
							'c' => 'DE',
							't' => time() - 500,
						),
					),
				)
			)
		);
		restore_current_blog();

		// The login happens on site 1, where the user is only a subscriber.
		$this->login( $user, self::IP_B, 'FR' );
		$this->assertSame( array(), $this->rows(), 'nothing on the site where they are not an administrator' );

		switch_to_blog( $site );
		$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}bouncer_log WHERE rule = 'admin_login'", ARRAY_A ); // phpcs:ignore WordPress.DB
		$this->assertCount( 1, $rows, 'recorded on the site where they are an administrator' );
		$this->assertStringContainsString( 'new location', $rows[0]['reason'] );
		$this->assertCount( 2, $this->history( $user )['e'], 'assessed against that site\'s history' );
		restore_current_blog();

		$mail = $this->mails();
		$this->assertCount( 1, $mail, 'the alert for that site is queued' );
		$this->assertSame( get_blog_option( $site, 'admin_email' ), $mail[0]['to'][0][0], 'to that site\'s recipients' );
	}
}
