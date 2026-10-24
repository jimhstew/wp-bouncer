<?php
/**
 * Early application-password check used by the WAF's JSON exemption.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Login;

use WPBouncer\Login\BasicAuthEditor;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Login\BasicAuthEditor
 */
final class BasicAuthEditorTest extends IntegrationTestCase {

	/** @var string[] */
	private array $fired = array();

	public function set_up() {
		parent::set_up();
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		$this->fired = array();
		foreach ( array( 'application_password_did_authenticate', 'application_password_failed_authentication', 'application_password_is_api_request', 'wp_authenticate_user', 'authenticate', 'set_current_user' ) as $hook ) {
			add_filter(
				$hook,
				function ( $value = null ) use ( $hook ) {
					$this->fired[] = $hook;
					return $value;
				},
				1,
				10
			);
		}
	}

	/**
	 * Create a user with an application password.
	 *
	 * @return array{0: \WP_User, 1: string, 2: string} User, plain password, UUID.
	 */
	private function user_with_password( string $role ): array {
		$user_id        = self::factory()->user->create( array( 'role' => $role ) );
		list( $plain, $item ) = \WP_Application_Passwords::create_new_application_password( $user_id, array( 'name' => 'test' ) );
		return array( get_userdata( $user_id ), $plain, $item['uuid'] );
	}

	/**
	 * A checker for a REST request (unless told otherwise).
	 *
	 * @param bool $api     Is it a REST or XML-RPC request?
	 * @param bool $refused Is it refused anyway?
	 */
	private function check( string $login, string $password, bool $locked = false, bool $api = true, bool $refused = false, ?callable $on_failure = null ): BasicAuthEditor {
		return new BasicAuthEditor(
			array(
				'PHP_AUTH_USER' => $login,
				'PHP_AUTH_PW'   => $password,
			),
			static fn(): bool => $api,
			static fn(): bool => $refused,
			static fn(): bool => $locked,
			$on_failure
		);
	}

	/** Count the times the stored password hashes were read (that is the moment before any hashing). */
	private function count_hash_reads(): \ArrayObject {
		$reads = new \ArrayObject( array( 'n' => 0 ) );
		add_filter(
			'get_user_metadata',
			static function ( $value, $object_id, $meta_key ) use ( $reads ) {
				if ( '_application_passwords' === $meta_key ) {
					$reads['n'] = $reads['n'] + 1;
				}
				return $value;
			},
			10,
			3
		);
		return $reads;
	}

	public function test_correct_password_of_an_editor(): void {
		list( $user, $plain ) = $this->user_with_password( 'editor' );
		$check                = $this->check( $user->user_login, $plain );
		$this->assertTrue( $check->is_editor() );
		$this->assertFalse( $check->is_admin() );
		// The displayed form has spaces; they are ignored, as in core.
		$this->assertTrue( $this->check( $user->user_login, chunk_split( $plain, 4, ' ' ) )->is_editor() );
		// By e-mail address too.
		$this->assertTrue( $this->check( $user->user_email, $plain )->is_editor() );
	}

	public function test_administrator_is_recognised_as_admin(): void {
		list( $user, $plain ) = $this->user_with_password( 'administrator' );
		$this->assertTrue( $this->check( $user->user_login, $plain )->is_admin() );
	}

	public function test_failures(): void {
		list( $user, $plain ) = $this->user_with_password( 'editor' );
		$this->assertFalse( $this->check( 'nobody-' . wp_generate_password( 6, false ), $plain )->is_editor(), 'unknown user' );
		$this->assertFalse( $this->check( $user->user_login, 'wrongwrongwrongwrongwrongx' )->is_editor(), 'wrong password' );
		$this->assertFalse( $this->check( $user->user_login, '' )->is_editor(), 'empty password' );
		$this->assertFalse( $this->check( $user->user_login, $plain, true )->is_editor(), 'locked-out client' );

		list( $sub, $sub_plain ) = $this->user_with_password( 'subscriber' );
		$this->assertFalse( $this->check( $sub->user_login, $sub_plain )->is_editor(), 'no edit_posts' );

		add_filter( 'wp_is_application_passwords_available_for_user', '__return_false' );
		$this->assertFalse( $this->check( $user->user_login, $plain )->is_editor(), 'application passwords not available' );
	}

	public function test_nothing_is_hashed_when_a_cheaper_check_already_fails(): void {
		list( $user, $plain )    = $this->user_with_password( 'editor' );
		list( $sub, $sub_plain ) = $this->user_with_password( 'subscriber' );
		$reads                   = $this->count_hash_reads();
		$this->check( $user->user_login, $plain, true )->is_editor();
		$this->check( $sub->user_login, $sub_plain )->is_editor();
		$this->check( 'nobody-at-all', $plain )->is_editor();
		$this->check( $user->user_login, $plain, false, true, true )->is_editor();
		$this->assertSame( 0, $reads['n'] );
		$this->assertTrue( $this->check( $user->user_login, $plain )->is_editor() );
		$this->assertSame( 1, $reads['n'] );
	}

	public function test_credentials_mean_nothing_off_the_api_paths(): void {
		list( $user, $plain ) = $this->user_with_password( 'administrator' );
		$reads                = $this->count_hash_reads();
		$check                = $this->check( $user->user_login, $plain, false, false );
		$this->assertFalse( $check->is_editor() );
		$this->assertFalse( $check->is_admin() );
		$this->assertSame( 0, $reads['n'], 'no lookup, no hashing' );
	}

	public function test_a_refused_request_is_never_an_editor(): void {
		list( $user, $plain ) = $this->user_with_password( 'editor' );
		$this->assertFalse( $this->check( $user->user_login, $plain, false, true, true )->is_editor() );
	}

	public function test_a_wrong_password_is_reported_once_and_nothing_is_stored(): void {
		list( $user, $plain ) = $this->user_with_password( 'editor' );
		$failed               = array();
		$report               = static function ( string $name ) use ( &$failed ): void {
			$failed[] = $name;
		};
		global $wpdb;
		$rows = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$this->assertFalse( $this->check( $user->user_login, 'wrongwrongwrongwrongx', false, true, false, $report )->is_editor() );
		$this->assertSame( array( $user->user_login ), $failed );
		$this->assertSame( $rows, (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options}" ), 'no option or transient per password' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		// The same checker answers from its result: no second report.
		$check = $this->check( $user->user_login, 'wrongwrongwrongwrongx', false, true, false, $report );
		$check->is_editor();
		$check->is_admin();
		$this->assertCount( 2, $failed );
		// A right password, a locked-out client, an unknown user or a subscriber report nothing.
		$failed = array();
		$this->check( $user->user_login, $plain, false, true, false, $report )->is_editor();
		$this->check( $user->user_login, $plain, true, true, false, $report )->is_editor();
		$this->check( 'nobody-at-all', $plain, false, true, false, $report )->is_editor();
		$this->assertSame( array(), $failed );
	}

	public function test_an_errors_hook_can_veto_the_password(): void {
		list( $user, $plain ) = $this->user_with_password( 'editor' );
		$veto                 = static function ( $error ) {
			$error->add( 'blocked', 'Not from here.' );
		};
		add_action( 'wp_authenticate_application_password_errors', $veto );
		$this->assertFalse( $this->check( $user->user_login, $plain )->is_editor() );
		remove_action( 'wp_authenticate_application_password_errors', $veto );
		$this->assertTrue( $this->check( $user->user_login, $plain )->is_editor() );
	}

	public function test_only_the_first_twenty_stored_passwords_are_compared(): void {
		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$plains  = array();
		for ( $i = 0; $i < 22; $i++ ) {
			list( $plains[], ) = \WP_Application_Passwords::create_new_application_password( $user_id, array( 'name' => 'p' . $i ) );
		}
		$login = get_userdata( $user_id )->user_login;
		$this->assertTrue( $this->check( $login, $plains[19] )->is_editor(), 'the 20th counts' );
		$this->assertFalse( $this->check( $login, $plains[20] )->is_editor(), 'the 21st does not' );
	}

	public function test_the_check_has_no_side_effects(): void {
		list( $user, $plain, $uuid ) = $this->user_with_password( 'editor' );
		$before_user                 = get_current_user_id();
		$before                      = \WP_Application_Passwords::get_user_application_password( $user->ID, $uuid );
		$this->assertNull( $before['last_used'] );
		$this->fired = array();

		$this->assertTrue( $this->check( $user->user_login, $plain )->is_editor() );
		$this->assertFalse( $this->check( $user->user_login, 'wrongwrongwrongwrongwrongx' )->is_editor() );

		$after = \WP_Application_Passwords::get_user_application_password( $user->ID, $uuid );
		$this->assertSame( $before, $after, 'last_used / last_ip unchanged' );
		$this->assertSame( array(), $this->fired, 'no authentication hooks fired' );
		$this->assertSame( $before_user, get_current_user_id(), 'the current user is untouched' );
	}
}
