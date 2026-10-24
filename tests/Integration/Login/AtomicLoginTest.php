<?php
/**
 * Plugin's login hooks with the reservation counter in the database (RT-08).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Login;

use WPBouncer\Storage\TableCounter;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Plugin::reserve_login_attempt
 * @covers \WPBouncer\Plugin::filter_authenticate
 */
final class AtomicLoginTest extends IntegrationTestCase {

	private const KEY = 'login_n:203.0.113.9';

	public function set_up() {
		parent::set_up();
		$this->fake_request( array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		$this->plugin->attempt_counter()->delete( self::KEY );
	}

	/** One full authentication that fails. */
	private function failed_login(): mixed {
		$this->plugin->reserve_login_attempt( null, 'someone', 'wrong' );
		$result = $this->plugin->filter_authenticate( new \WP_Error( 'incorrect_password', 'Specific' ) );
		do_action( 'wp_login_failed', 'someone' );
		return $result;
	}

	public function test_without_a_persistent_object_cache_the_table_counter_is_used(): void {
		$this->assertInstanceOf( TableCounter::class, $this->plugin->attempt_counter() );
	}

	public function test_the_reservation_hook_runs_before_core_authenticators(): void {
		$this->assertSame( 1, has_filter( 'authenticate', array( $this->plugin, 'reserve_login_attempt' ) ) );
	}

	public function test_the_fifth_failure_locks_and_the_sixth_attempt_is_refused_whatever_the_password(): void {
		for ( $i = 1; $i <= 4; $i++ ) {
			$this->assertWPError( $this->failed_login() );
			$this->assertNull( $this->plugin->store()->get( 'login_lock:203.0.113.9' ), "no lockout after $i" );
		}
		$this->failed_login();
		$this->assertNotNull( $this->plugin->store()->get( 'login_lock:203.0.113.9' ), 'locked after the fifth' );

		$user = new \WP_User( 1 );
		$this->plugin->reserve_login_attempt( null, 'someone', 'right' );
		$result = $this->plugin->filter_authenticate( $user );
		$this->assertWPError( $result );
		$this->assertSame( 'wp_bouncer_locked_out', $result->get_error_code() );
	}

	public function test_a_burst_past_the_maximum_is_refused_before_a_lockout_is_written(): void {
		$counter = $this->plugin->attempt_counter();
		for ( $i = 0; $i < 5; $i++ ) {
			$counter->add_or_increment( self::KEY, 900 ); // Five attempts already reserved by parallel requests.
		}
		$this->plugin->reserve_login_attempt( null, 'someone', 'right' ); // The sixth.
		$result = $this->plugin->filter_authenticate( new \WP_User( 1 ) );
		$this->assertWPError( $result );
		$this->assertSame( 'wp_bouncer_locked_out', $result->get_error_code() );
	}

	public function test_a_successful_login_gives_the_reservation_back(): void {
		$user = new \WP_User( 1 );
		$this->plugin->reserve_login_attempt( null, 'someone', 'right' );
		$this->assertSame( 1, $this->plugin->attempt_counter()->get( self::KEY ) );
		$this->assertSame( $user, $this->plugin->filter_authenticate( $user ) );
		$this->assertSame( 0, $this->plugin->attempt_counter()->get( self::KEY ) );
	}

	public function test_an_empty_password_is_not_counted(): void {
		$this->plugin->reserve_login_attempt( null, 'someone', '' );
		$this->assertSame( 0, $this->plugin->attempt_counter()->get( self::KEY ) );
	}

	public function test_unlocking_clears_the_counter(): void {
		for ( $i = 0; $i < 3; $i++ ) {
			$this->failed_login();
		}
		$this->assertSame( 3, $this->plugin->attempt_counter()->get( self::KEY ) );
		$this->plugin->login_guard()->clear( '203.0.113.9' );
		$this->assertSame( 0, $this->plugin->attempt_counter()->get( self::KEY ) );
	}

	public function test_the_object_cache_is_used_only_when_the_site_opts_in(): void {
		wp_using_ext_object_cache( true );
		try {
			$this->assertInstanceOf( TableCounter::class, $this->plugin->attempt_counter(), 'a persistent cache alone is not enough' );
			add_filter( 'wp_bouncer_atomic_object_cache', '__return_true' );
			$this->assertInstanceOf( \WPBouncer\Storage\ObjectCacheCounter::class, $this->plugin->attempt_counter() );
		} finally {
			remove_filter( 'wp_bouncer_atomic_object_cache', '__return_true' );
			wp_using_ext_object_cache( false );
		}
	}

	public function test_wp_login_releases_the_reservation_too(): void {
		$this->plugin->reserve_login_attempt( null, 'someone', 'right' );
		$this->assertSame( 1, $this->plugin->attempt_counter()->get( self::KEY ) );
		do_action( 'wp_login', 'someone', new \WP_User( 1 ) );
		$this->assertSame( 0, $this->plugin->attempt_counter()->get( self::KEY ) );
		do_action( 'wp_login', 'someone', new \WP_User( 1 ) );
		$this->assertSame( 0, $this->plugin->attempt_counter()->get( self::KEY ), 'idempotent' );
	}

	/* ---------------- application passwords (REST Basic auth) ---------------- */

	public function test_app_password_failures_are_counted_and_lock_the_subject(): void {
		$_SERVER['PHP_AUTH_USER'] = 'someone';
		$_SERVER['PHP_AUTH_PW']   = 'wrong';
		for ( $i = 1; $i <= 4; $i++ ) {
			do_action( 'application_password_failed_authentication', new \WP_Error( 'incorrect_password', 'x' ) );
		}
		$this->assertSame( 4, $this->plugin->attempt_counter()->get( self::KEY ) );
		$this->assertNull( $this->plugin->store()->get( 'login_lock:203.0.113.9' ) );
		do_action( 'application_password_failed_authentication', new \WP_Error( 'incorrect_password', 'x' ) );
		$this->assertNotNull( $this->plugin->store()->get( 'login_lock:203.0.113.9' ) );
	}

	public function test_an_app_password_failure_that_already_holds_a_reservation_is_not_counted_twice(): void {
		$this->plugin->reserve_login_attempt( null, 'someone', 'wrong' );
		do_action( 'application_password_failed_authentication', new \WP_Error( 'incorrect_password', 'x' ) );
		$this->assertSame( 1, $this->plugin->attempt_counter()->get( self::KEY ) );
	}

	public function test_a_locked_out_client_is_not_allowed_to_try_application_passwords(): void {
		$this->assertTrue( apply_filters( 'application_password_is_api_request', true ) );
		for ( $i = 0; $i < 5; $i++ ) {
			$this->failed_login();
		}
		$this->assertFalse( apply_filters( 'application_password_is_api_request', true ) );
		$this->assertFalse( apply_filters( 'application_password_is_api_request', false ) );

		$_SERVER['PHP_AUTH_USER'] = 'someone';
		$_SERVER['PHP_AUTH_PW']   = 'right';
		$result                   = apply_filters( 'rest_authentication_errors', null );
		$this->assertWPError( $result );
		$this->assertSame( 'wp_bouncer_locked_out', $result->get_error_code() );
		$this->assertSame( 403, $result->get_error_data()['status'] );
	}

	public function test_rest_credential_errors_are_made_generic(): void {
		foreach ( array( 'invalid_username', 'invalid_email', 'incorrect_password', 'application_passwords_disabled_for_user' ) as $code ) {
			$result = $this->plugin->filter_rest_authentication_errors( new \WP_Error( $code, 'Unknown username.', array( 'status' => 401 ) ) );
			$this->assertSame( 'wp_bouncer_invalid_credentials', $result->get_error_code(), $code );
			$this->assertStringNotContainsString( 'Unknown', $result->get_error_message() );
		}
		$other = new \WP_Error( 'rest_forbidden', 'Nope' );
		$this->assertSame( $other, $this->plugin->filter_rest_authentication_errors( $other ) );
		$this->assertTrue( $this->plugin->filter_rest_authentication_errors( true ) );
	}

	public function test_rest_basic_auth_failure_through_core_is_counted_and_generic(): void {
		$user = self::factory()->user->create(
			array(
				'user_login' => 'wpb_s10_app',
				'role'       => 'administrator',
			)
		);
		\WP_Application_Passwords::create_new_application_password( $user, array( 'name' => 'wpb test' ) ); // Core only checks them once one exists.
		$_SERVER['PHP_AUTH_USER'] = 'nobody-here';
		$_SERVER['PHP_AUTH_PW']   = 'abcd efgh ijkl mnop qrst uvwx';
		add_filter( 'application_password_is_api_request', '__return_true' );
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		global $wp_rest_application_password_status;
		$result = wp_authenticate_application_password( null, 'nobody-here', $_SERVER['PHP_AUTH_PW'] );
		$this->assertWPError( $result );
		$this->assertSame( 1, $this->plugin->attempt_counter()->get( self::KEY ), 'counted once' );
		$wp_rest_application_password_status = $result;
		$final                               = apply_filters( 'rest_authentication_errors', null );
		$this->assertSame( 'wp_bouncer_invalid_credentials', $final->get_error_code() );
		$wp_rest_application_password_status = null;
		wp_delete_user( $user );
	}

	public function test_a_rest_basic_auth_check_reserves_and_a_success_gives_it_back(): void {
		$_SERVER['PHP_AUTH_USER'] = 'someone';
		$_SERVER['PHP_AUTH_PW']   = 'abcd efgh';
		$this->assertTrue( apply_filters( 'application_password_is_api_request', true ) );
		$this->assertSame( 1, $this->plugin->attempt_counter()->get( self::KEY ), 'reserved before the check' );
		do_action( 'application_password_did_authenticate', new \WP_User( 1 ), array() );
		$this->assertSame( 0, $this->plugin->attempt_counter()->get( self::KEY ), 'released on success' );
	}

	public function test_a_rest_basic_auth_failure_settles_the_reservation_once(): void {
		$_SERVER['PHP_AUTH_USER'] = 'someone';
		$_SERVER['PHP_AUTH_PW']   = 'wrong';
		apply_filters( 'application_password_is_api_request', true );
		do_action( 'application_password_failed_authentication', new \WP_Error( 'incorrect_password', 'x' ) );
		$this->assertSame( 1, $this->plugin->attempt_counter()->get( self::KEY ), 'one attempt, one failure' );
	}

	public function test_a_burst_of_rest_checks_is_limited_like_other_logins(): void {
		$_SERVER['PHP_AUTH_USER'] = 'someone';
		$_SERVER['PHP_AUTH_PW']   = 'wrong';
		$counter                  = $this->plugin->attempt_counter();
		for ( $i = 0; $i < 5; $i++ ) {
			$counter->add_or_increment( self::KEY, 900 ); // Five parallel checks already reserved.
		}
		$this->assertFalse( apply_filters( 'application_password_is_api_request', true ), 'the sixth is not even checked' );
		$result = apply_filters( 'rest_authentication_errors', null );
		$this->assertWPError( $result );
		$this->assertSame( 'wp_bouncer_locked_out', $result->get_error_code() );
	}

	public function test_rest_failures_feed_the_slash_48_counter(): void {
		$this->fake_request( array( 'REMOTE_ADDR' => '2001:db8:5:1::9' ) );
		$_SERVER['PHP_AUTH_USER'] = 'someone';
		$_SERVER['PHP_AUTH_PW']   = 'wrong';
		$wide                     = (string) \WPBouncer\Login\LoginGuard::wide_key( '2001:db8:5:1::9' );
		$this->plugin->attempt_counter()->delete( $wide );
		apply_filters( 'application_password_is_api_request', true );
		do_action( 'application_password_failed_authentication', new \WP_Error( 'incorrect_password', 'x' ) );
		do_action( 'application_password_failed_authentication', new \WP_Error( 'incorrect_password', 'x' ) );
		$this->assertSame( 2, $this->plugin->attempt_counter()->get( $wide ) );
		$this->plugin->attempt_counter()->delete( $wide );
	}

	public function test_the_wp_login_release_runs_before_other_wp_login_callbacks(): void {
		global $wp_filter;
		$priorities = array_keys( $wp_filter['wp_login']->callbacks );
		$this->assertLessThan( 0, min( $priorities ) );
	}
}
