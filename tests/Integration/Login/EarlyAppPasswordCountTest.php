<?php
/**
 * Wrong application passwords found by the early check are counted exactly once (release audit).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Login;

use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Plugin::count_early_app_password_failure
 * @covers \WPBouncer\Plugin::count_app_password_failure
 * @covers \WPBouncer\Login\BasicAuthEditor
 */
final class EarlyAppPasswordCountTest extends IntegrationTestCase {

	private const KEY = 'login_n:203.0.113.9';

	private int $hash_reads = 0;

	public function set_up() {
		parent::set_up();
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		$this->hash_reads = 0;
		add_filter(
			'get_user_metadata',
			function ( $value, $object_id, $meta_key ) {
				if ( '_application_passwords' === $meta_key ) {
					++$this->hash_reads;
				}
				return $value;
			},
			10,
			3
		);
		$this->fake_request();
		$this->plugin->attempt_counter()->delete( self::KEY );
	}

	/** One request to $uri carrying a wrong application password for the user. */
	private function wrong_password_request( string $uri, string $login, int $n = 0 ): void {
		$this->fake_request(
			array(
				'REQUEST_URI'   => $uri,
				'PHP_AUTH_USER' => $login,
				'PHP_AUTH_PW'   => 'wrongwrongwrongwrong' . $n,
			)
		);
		$this->assertFalse( $this->plugin->current_request()->can_edit_posts() );
	}

	private function editor_login(): string {
		$id = self::factory()->user->create( array( 'role' => 'editor' ) );
		\WP_Application_Passwords::create_new_application_password( $id, array( 'name' => 'x' ) );
		$this->hash_reads = 0; // Creating the password read the list too.
		return get_userdata( $id )->user_login;
	}

	public function test_xmlrpc_wrong_passwords_lock_the_client_out_and_stop_the_hashing(): void {
		$this->set_settings(
			array(
				'rules' => array(
					'xmlrpc' => array(
						'enabled' => true,
						'mode'    => 'block_all',
					),
				),
			)
		);
		$login = $this->editor_login();
		global $wpdb;
		for ( $i = 1; $i <= 5; $i++ ) {
			$this->wrong_password_request( '/xmlrpc.php', $login, $i );
		}
		$this->assertNotNull( $this->plugin->store()->get( 'login_lock:203.0.113.9' ), 'locked out after the fifth' );
		$this->assertSame( 5, $this->hash_reads );

		$this->hash_reads = 0;
		$this->wrong_password_request( '/xmlrpc.php', $login, 6 );
		$this->assertSame( 0, $this->hash_reads, 'no password is read or compared once locked out' );
		$this->assertSame( 0, (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '%basic_neg%'" ), 'nothing stored per password' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	public function test_a_rest_wrong_password_is_counted_once_when_core_counts_it_too(): void {
		$login = $this->editor_login();
		$this->wrong_password_request( '/wp-json/wp/v2/posts', $login );
		$this->assertSame( 1, $this->plugin->attempt_counter()->get( self::KEY ), 'counted by the early check' );
		do_action( 'application_password_failed_authentication', new \WP_Error( 'incorrect_password', 'x' ) );
		$this->assertSame( 1, $this->plugin->attempt_counter()->get( self::KEY ), "core's count for the same attempt is skipped" );
		// A second, separate failure in the same process counts again.
		do_action( 'application_password_failed_authentication', new \WP_Error( 'incorrect_password', 'x' ) );
		$this->assertSame( 2, $this->plugin->attempt_counter()->get( self::KEY ) );
	}

	/** One REST request with a wrong password, as core runs it: early count, lock check, failure hook. */
	private function full_rest_failure( string $login, int $n ): void {
		$this->wrong_password_request( '/wp-json/wp/v2/posts', $login, $n );
		$this->plugin->refuse_app_password_when_locked( true );
		do_action( 'application_password_failed_authentication', new \WP_Error( 'incorrect_password', 'x' ) );
	}

	public function test_one_wrong_rest_password_raises_both_counters_by_exactly_one(): void {
		$ip   = '2001:db8:1:2::9';
		$keys = array( \WPBouncer\Login\LoginGuard::attempts_key( $ip ), (string) \WPBouncer\Login\LoginGuard::wide_key( $ip ) );
		foreach ( $keys as $k ) {
			$this->plugin->attempt_counter()->delete( $k );
		}
		$login = $this->editor_login();
		$this->fake_request(
			array(
				'REMOTE_ADDR'   => $ip,
				'REQUEST_URI'   => '/wp-json/wp/v2/posts',
				'PHP_AUTH_USER' => $login,
				'PHP_AUTH_PW'   => 'wrongwrongwrongwrong0',
			)
		);
		$this->assertFalse( $this->plugin->current_request()->can_edit_posts() );
		$this->plugin->refuse_app_password_when_locked( true );
		do_action( 'application_password_failed_authentication', new \WP_Error( 'incorrect_password', 'x' ) );

		foreach ( $keys as $k ) {
			$this->assertSame( 1, $this->plugin->attempt_counter()->get( $k ), $k );
			$this->plugin->attempt_counter()->delete( $k );
		}
	}

	public function test_max_attempts_wrong_rest_passwords_lock_out_at_the_maximum(): void {
		$login = $this->editor_login();
		for ( $i = 1; $i <= 4; $i++ ) {
			$this->full_rest_failure( $login, $i );
			$this->assertNull( $this->plugin->store()->get( 'login_lock:203.0.113.9' ), "not locked after $i" );
		}
		$this->full_rest_failure( $login, 5 );
		$this->assertNotNull( $this->plugin->store()->get( 'login_lock:203.0.113.9' ), 'locked at the fifth' );
	}

	public function test_a_matching_wp_login_failed_is_skipped_too(): void {
		$login = $this->editor_login();
		$this->wrong_password_request( '/xmlrpc.php', $login );
		do_action( 'wp_login_failed', $login );
		$this->assertSame( 1, $this->plugin->attempt_counter()->get( self::KEY ) );
	}

	public function test_nothing_is_counted_off_the_api_paths(): void {
		$login = $this->editor_login();
		$this->wrong_password_request( '/wp-admin/admin-ajax.php', $login );
		$this->wrong_password_request( '/contact-us/', $login );
		$this->assertSame( 0, $this->hash_reads );
		$this->assertTrue( 0 === (int) $this->plugin->attempt_counter()->get( self::KEY ) );
	}
}
