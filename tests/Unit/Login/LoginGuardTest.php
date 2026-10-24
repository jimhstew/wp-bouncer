<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Login;

use PHPUnit\Framework\TestCase;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Login\LoginGuard;
use WPBouncer\Rules\LoginLockoutRule;
use WPBouncer\Tests\Support\MemoryStore;
use WPBouncer\Tests\Support\FrozenClock;
use WPBouncer\Tests\Support\MemoryBlockLog;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Login\LoginGuard
 * @covers \WPBouncer\Rules\LoginLockoutRule
 */
final class LoginGuardTest extends TestCase {

	private const IP = '203.0.113.10';

	private FrozenClock $clock;
	private MemoryStore $store;
	private MemoryBlockLog $log;

	protected function setUp(): void {
		$this->clock = new FrozenClock();
		$this->store = new MemoryStore( $this->clock );
		$this->log   = new MemoryBlockLog();
	}

	private function settings( array $overrides = array() ): array {
		return array_merge(
			array(
				'enabled'          => true,
				'max_attempts'     => 3,
				'window_minutes'   => 10,
				'lockout_minutes'  => 30,
				'banned_usernames' => array( 'admin' ),
				'generic_errors'   => true,
			),
			$overrides
		);
	}

	private function guard( array $overrides = array() ): LoginGuard {
		return new LoginGuard( $this->settings( $overrides ), $this->store, $this->log, $this->clock );
	}

	public function test_locks_out_after_max_attempts(): void {
		$guard = $this->guard();

		$this->assertFalse( $guard->record_failure( self::IP, 'alice' ) );
		$this->assertFalse( $guard->record_failure( self::IP, 'alice' ) );
		$this->assertFalse( $guard->is_locked_out( self::IP ) );

		$this->assertTrue( $guard->record_failure( self::IP, 'alice' ) );
		$this->assertTrue( $guard->is_locked_out( self::IP ) );
		$this->assertSame( 30 * 60, $guard->lockout_remaining( self::IP ) );

		$this->assertCount( 1, $this->log->entries );
		$this->assertSame( BlockLogInterface::ACTION_LOCKOUT, $this->log->entries[0]['action'] );
		$this->assertSame( 'login_lockout', $this->log->entries[0]['rule'] );
		$this->assertStringContainsString( '3 failed logins', $this->log->entries[0]['reason'] );
	}

	public function test_unknown_username_is_not_logged(): void {
		$guard = new LoginGuard( $this->settings(), $this->store, $this->log, $this->clock, static fn ( string $n ): ?string => null );
		$guard->record_failure( self::IP, 'MyP@ssw0rd!' );
		$guard->record_failure( self::IP, 'MyP@ssw0rd!' );
		$guard->record_failure( self::IP, 'MyP@ssw0rd!' );
		$reason = $this->log->entries[0]['reason'];
		$this->assertStringNotContainsString( 'P@ssw0rd', $reason );
		$this->assertStringContainsString( 'unknown username', $reason );
		$this->assertStringNotContainsString( 'characters', $reason );
	}

	public function test_username_without_a_callable_is_treated_as_unknown(): void {
		$guard = $this->guard();
		for ( $i = 0; $i < 3; $i++ ) {
			$guard->record_failure( self::IP, 'alice@example.org' );
		}
		$this->assertStringNotContainsString( 'alice', $this->log->entries[0]['reason'] );
	}

	public function test_existing_username_is_logged(): void {
		$guard = new LoginGuard( $this->settings(), $this->store, $this->log, $this->clock, static fn ( string $n ): ?string => 'alice' === strtolower( $n ) ? 'alice' : null );
		for ( $i = 0; $i < 3; $i++ ) {
			$guard->record_failure( self::IP, 'ALICE' );
		}
		$this->assertStringNotContainsString( 'ALICE', $this->log->entries[0]['reason'], 'canonical login only' );
		$this->assertStringContainsString( '"alice"', $this->log->entries[0]['reason'] );
	}

	public function test_banned_username_is_logged(): void {
		$guard = $this->guard();
		$guard->record_failure( self::IP, 'admin' );
		$this->assertStringContainsString( '"admin"', $this->log->entries[0]['reason'] );
	}

	public function test_lockout_expires(): void {
		$guard = $this->guard();
		for ( $i = 0; $i < 3; $i++ ) {
			$guard->record_failure( self::IP, 'alice' );
		}
		$this->clock->advance( 30 * 60 - 1 );
		$this->assertTrue( $guard->is_locked_out( self::IP ) );
		$this->clock->advance( 1 );
		$this->assertFalse( $guard->is_locked_out( self::IP ) );
	}

	public function test_failures_outside_window_are_forgotten(): void {
		$guard = $this->guard();
		$guard->record_failure( self::IP, 'alice' );
		$guard->record_failure( self::IP, 'alice' );
		$this->clock->advance( 10 * 60 );
		$this->assertFalse( $guard->record_failure( self::IP, 'alice' ), 'window reset, so this is failure #1' );
		$this->assertFalse( $guard->is_locked_out( self::IP ) );
	}

	public function test_banned_username_locks_out_immediately(): void {
		$guard = $this->guard();
		$this->assertTrue( $guard->record_failure( self::IP, 'Admin' ) );
		$this->assertTrue( $guard->is_locked_out( self::IP ) );
		$this->assertStringContainsString( 'banned username', $this->log->entries[0]['reason'] );
	}

	public function test_ips_are_tracked_independently(): void {
		$guard = $this->guard();
		for ( $i = 0; $i < 3; $i++ ) {
			$guard->record_failure( self::IP, 'alice' );
		}
		$this->assertFalse( $guard->is_locked_out( '198.51.100.1' ) );
	}

	public function test_failures_while_locked_out_do_not_relog(): void {
		$guard = $this->guard();
		$guard->record_failure( self::IP, 'admin' );
		$guard->record_failure( self::IP, 'admin' );
		$this->assertCount( 1, $this->log->entries );
	}

	public function test_disabled_guard_does_nothing(): void {
		$guard = $this->guard( array( 'enabled' => false ) );
		$this->assertFalse( $guard->record_failure( self::IP, 'admin' ) );
		$this->assertFalse( $guard->is_locked_out( self::IP ) );
		$this->assertFalse( $guard->wants_generic_errors() );
	}

	public function test_clear_lifts_lockout(): void {
		$guard = $this->guard();
		$guard->record_failure( self::IP, 'admin' );
		$guard->clear( self::IP );
		$this->assertFalse( $guard->is_locked_out( self::IP ) );
	}

	public function test_context_is_attached_to_log(): void {
		$this->guard()->record_failure(
			self::IP,
			'admin',
			array(
				'uri'     => '/wp-login.php',
				'country' => 'DE',
			)
		);
		$this->assertSame( '/wp-login.php', $this->log->entries[0]['uri'] );
		$this->assertSame( 'DE', $this->log->entries[0]['country'] );
		$this->assertSame( self::IP, $this->log->entries[0]['ip'] );
	}

	public function test_rule_refuses_login_posts_from_locked_out_ip(): void {
		$guard = $this->guard();
		$rule  = new LoginLockoutRule( $this->settings(), $guard );
		$post  = Requests::make(
			array(
				'uri'    => '/wp-login.php',
				'method' => 'POST',
				'ip'     => self::IP,
			)
		);

		$this->assertNull( $rule->inspect( $post ) );

		$guard->record_failure( self::IP, 'admin' );

		$verdict = $rule->inspect( $post );
		$this->assertNotNull( $verdict );
		$this->assertSame( 30 * 60, $verdict->retry_after() );
		$this->assertNotNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/xmlrpc.php',
						'method' => 'POST',
						'ip'     => self::IP,
					)
				)
			)
		);

		// Viewing the form and browsing the site still work.
		$this->assertNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri' => '/wp-login.php',
						'ip'  => self::IP,
					)
				)
			)
		);
		$this->assertNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/',
						'method' => 'POST',
						'ip'     => self::IP,
					)
				)
			)
		);
	}

	public function test_rule_ignores_a_lockout_for_a_client_that_cannot_be_banned(): void {
		$guard = $this->guard();
		$rule  = new LoginLockoutRule( $this->settings(), $guard );
		$guard->record_failure( self::IP, 'admin' );

		$this->assertNotNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/wp-login.php',
						'method' => 'POST',
						'ip'     => self::IP,
					)
				)
			)
		);
		$this->assertNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri'      => '/wp-login.php',
						'method'   => 'POST',
						'ip'       => self::IP,
						'bannable' => false,
					)
				)
			)
		);
	}

	public function test_login_lockout_still_acts_for_an_unlisted_public_peer(): void {
		$resolver = new \WPBouncer\Firewall\IpResolver( 'x_real_ip', array( '198.51.100.1' ) );
		$server   = array(
			'REMOTE_ADDR'    => '203.0.113.7',
			'HTTP_X_REAL_IP' => '203.0.113.99',
		);
		$ip       = $resolver->resolve( $server );
		$this->assertTrue( \WPBouncer\Support\IpUtils::is_bannable( $ip, $resolver->proxies(), $resolver->suspends_bans( $server ) ) );
		$guard = $this->guard();
		$rule  = new LoginLockoutRule( $this->settings(), $guard );
		$guard->record_failure( $ip, 'admin' );
		$this->assertNotNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/wp-login.php',
						'method' => 'POST',
						'ip'     => $ip,
					)
				)
			)
		);
	}
}
