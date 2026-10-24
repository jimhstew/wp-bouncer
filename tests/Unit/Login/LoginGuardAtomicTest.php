<?php
/**
 * RT-08 (atomic reservation) and RT-07 (IPv6 subjects) for LoginGuard.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Login;

use PHPUnit\Framework\TestCase;
use WPBouncer\Login\LoginGuard;
use WPBouncer\Tests\Support\FrozenClock;
use WPBouncer\Tests\Support\MemoryAtomicCounter;
use WPBouncer\Tests\Support\MemoryBlockLog;
use WPBouncer\Tests\Support\MemoryStore;

/**
 * @covers \WPBouncer\Login\LoginGuard
 */
final class LoginGuardAtomicTest extends TestCase {

	private const IP = '203.0.113.10';

	private FrozenClock $clock;
	private MemoryStore $store;
	private MemoryAtomicCounter $counter;
	private MemoryBlockLog $log;

	protected function setUp(): void {
		$this->clock   = new FrozenClock();
		$this->store   = new MemoryStore( $this->clock );
		$this->counter = new MemoryAtomicCounter( $this->clock );
		$this->log     = new MemoryBlockLog();
	}

	/** One guard per simulated request, sharing the stores. */
	private function request( bool $atomic = true ): LoginGuard {
		return new LoginGuard(
			array(
				'enabled'         => true,
				'max_attempts'    => 3,
				'window_minutes'  => 10,
				'lockout_minutes' => 30,
			),
			$this->store,
			$this->log,
			$this->clock,
			null,
			$atomic ? $this->counter : null
		);
	}

	public function test_parallel_failures_are_all_counted(): void {
		// Every request reserves before any of them settles: the interleaving that broke the old counter.
		$requests = array();
		for ( $i = 1; $i <= 6; $i++ ) {
			$requests[ $i ] = $this->request();
			$this->assertSame( $i, $requests[ $i ]->reserve( self::IP ) );
		}
		$this->assertSame( 6, $this->request()->failures( self::IP ) );

		foreach ( $requests as $n => $guard ) {
			$refuse = $guard->refusal_seconds( self::IP );
			if ( $n <= 3 ) {
				$this->assertSame( 0, $refuse, "attempt $n may check its password" );
			} else {
				$this->assertGreaterThan( 0, $refuse, "attempt $n is refused whatever the password" );
			}
		}
	}

	public function test_lockout_is_placed_once_the_maximum_is_reached(): void {
		$requests = array();
		for ( $i = 1; $i <= 5; $i++ ) {
			$requests[ $i ] = $this->request();
			$requests[ $i ]->reserve( self::IP );
		}
		$this->assertFalse( $requests[1]->record_failure( self::IP, 'alice' ) );
		$this->assertFalse( $requests[2]->record_failure( self::IP, 'alice' ) );
		$this->assertTrue( $requests[3]->record_failure( self::IP, 'alice' ) );
		$this->assertTrue( $this->request()->is_locked_out( self::IP ) );
		$this->assertCount( 1, $this->log->entries );
		// The late ones see the lockout and don't log again.
		$this->assertFalse( $requests[4]->record_failure( self::IP, 'alice' ) );
		$this->assertCount( 1, $this->log->entries );
		$this->assertGreaterThan( 0, $requests[5]->refusal_seconds( self::IP ) );
	}

	public function test_correct_password_on_the_last_parallel_attempt_is_refused(): void {
		$requests = array();
		for ( $i = 1; $i <= 6; $i++ ) {
			$requests[ $i ] = $this->request();
			$requests[ $i ]->reserve( self::IP );
		}
		// max+3 attempts: the 6th has the right password, but it is past the limit.
		$this->assertGreaterThan( 0, $requests[6]->refusal_seconds( self::IP ) );
	}

	public function test_success_releases_the_reservation(): void {
		$guard = $this->request();
		$guard->reserve( self::IP );
		$this->assertSame( 1, $guard->failures( self::IP ) );
		$guard->release( self::IP );
		$this->assertSame( 0, $guard->failures( self::IP ) );
		$guard->release( self::IP );
		$this->assertSame( 0, $guard->failures( self::IP ), 'a second release is a no-op' );
	}

	public function test_failure_without_a_reservation_still_counts(): void {
		$guard = $this->request();
		$guard->record_failure( self::IP, 'alice' );
		$this->assertSame( 1, $guard->failures( self::IP ) );
	}

	public function test_failure_after_reservation_is_not_counted_twice(): void {
		$guard = $this->request();
		$guard->reserve( self::IP );
		$guard->record_failure( self::IP, 'alice' );
		$this->assertSame( 1, $guard->failures( self::IP ) );
	}

	public function test_window_expiry_resets_the_count(): void {
		$guard = $this->request();
		$guard->reserve( self::IP );
		$guard->reserve( self::IP );
		$this->clock->advance( 10 * 60 );
		$this->assertSame( 1, $this->request()->reserve( self::IP ) );
	}

	public function test_loopback_is_not_reserved(): void {
		$guard = $this->request();
		$this->assertSame( 0, $guard->reserve( '127.0.0.1' ) );
		$this->assertFalse( $guard->record_failure( '::1', 'alice' ) );
	}

	public function test_without_a_counter_reserve_does_nothing(): void {
		$guard = $this->request( false );
		$this->assertSame( 0, $guard->reserve( self::IP ) );
		$guard->release( self::IP );
		$this->assertSame( 0, $guard->refusal_seconds( self::IP ) );
	}

	public function test_without_a_counter_failures_at_the_limit_are_refused(): void {
		$guard = $this->request( false );
		$this->store->set( LoginGuard::failures_key( self::IP ), 3, 600 );
		$this->assertSame( 60, $guard->refusal_seconds( self::IP ) );
	}

	public function test_five_addresses_in_one_slash_64_cause_a_lockout(): void {
		$guard  = $this->request( false );
		$locked = false;
		for ( $i = 1; $i <= 3; $i++ ) {
			$locked = $guard->record_failure( "2001:db8:1:2::$i", 'alice' );
		}
		$this->assertTrue( $locked );
		$this->assertTrue( $guard->is_locked_out( '2001:db8:1:2:aaaa:bbbb:cccc:dddd' ) );
		$this->assertFalse( $guard->is_locked_out( '2001:db8:1:3::1' ), 'another /64 is independent' );
	}

	public function test_atomic_mode_groups_a_slash_64_too(): void {
		$guard = $this->request();
		$this->assertSame( 1, $guard->reserve( '2001:db8:1:2::1' ) );
		$this->assertSame( 2, $this->request()->reserve( '2001:db8:1:2::2' ) );
		$this->assertSame( 1, $this->request()->reserve( '2001:db8:1:3::1' ) );
	}

	public function test_unlock_of_any_address_in_the_slash_64_clears_it(): void {
		$guard = $this->request();
		for ( $i = 1; $i <= 3; $i++ ) {
			$guard->reserve( "2001:db8:1:2::$i" );
			$guard->record_failure( "2001:db8:1:2::$i", 'alice' );
		}
		$this->assertTrue( $guard->is_locked_out( '2001:db8:1:2::99' ) );
		$guard->clear( '2001:db8:1:2::77' );
		$this->assertFalse( $guard->is_locked_out( '2001:db8:1:2::1' ) );
		$this->assertSame( 0, $guard->failures( '2001:db8:1:2::1' ) );
	}

	public function test_unlock_also_clears_keys_from_before_the_upgrade(): void {
		$guard = $this->request();
		// Format used by 1.1.x: the exact string.
		$this->store->set( 'login_lock:2001:db8:1:2::5', $this->clock->now() + 600, 600 );
		$this->store->set( 'login_fail:2001:db8:1:2::5', 2, 600 );
		$guard->clear( '2001:db8:1:2::5' );
		$this->assertNull( $this->store->get( 'login_lock:2001:db8:1:2::5' ) );
		$this->assertNull( $this->store->get( 'login_fail:2001:db8:1:2::5' ) );
	}

	public function test_mapped_and_plain_ipv4_share_keys(): void {
		$this->assertSame( LoginGuard::lockout_key( '1.2.3.4' ), LoginGuard::lockout_key( '::ffff:1.2.3.4' ) );
		$this->assertSame( LoginGuard::attempts_key( '1.2.3.4' ), LoginGuard::attempts_key( '::ffff:102:304' ) );
	}

	public function test_ipv4_keys_keep_their_1_1_format(): void {
		$this->assertSame( 'login_lock:203.0.113.10', LoginGuard::lockout_key( self::IP ) );
		$this->assertSame( 'login_fail:203.0.113.10', LoginGuard::failures_key( self::IP ) );
	}

	/** The /48 limit is 3 x 8 = 24. Nine attacker /64s make 5 attempts each: 45. */
	private function flood_the_slash_48(): void {
		for ( $net = 1; $net <= 9; $net++ ) {
			$ip = sprintf( '2001:db8:5:%x::1', $net );
			for ( $i = 0; $i < 5; $i++ ) {
				$guard = $this->request();
				$guard->reserve( $ip );
				$guard->record_failure( $ip, 'alice' );
			}
		}
	}

	public function test_a_flooded_slash_48_never_locks_or_refuses_an_innocent_neighbour(): void {
		$this->flood_the_slash_48();
		$this->assertTrue( $this->request()->is_locked_out( '2001:db8:5:1::1' ), 'the attacker /64s are locked' );

		$neighbour = '2001:db8:5:99::7';
		$guard     = $this->request();
		$this->assertSame( 1, $guard->reserve( $neighbour ) );
		$this->assertSame( 0, $guard->refusal_seconds( $neighbour ), 'a correct password still gets checked' );
		$guard->release( $neighbour );
		$this->assertFalse( $this->request()->is_locked_out( $neighbour ) );
	}

	public function test_a_neighbours_single_typo_is_not_a_lockout(): void {
		$this->flood_the_slash_48();
		$neighbour = '2001:db8:5:99::7';
		$guard     = $this->request();
		$guard->reserve( $neighbour );
		$this->assertFalse( $guard->record_failure( $neighbour, 'alice' ) );
		$this->assertFalse( $this->request()->is_locked_out( $neighbour ) );
		// A correct password on the next try still works.
		$next = $this->request();
		$next->reserve( $neighbour );
		$this->assertSame( 0, $next->refusal_seconds( $neighbour ) );
	}

	public function test_while_the_slash_48_is_hot_a_slash_64_with_a_failure_is_locked_at_two(): void {
		$this->flood_the_slash_48();
		$ip    = '2001:db8:5:99::7';
		$first = $this->request();
		$first->reserve( $ip );
		$this->assertFalse( $first->record_failure( $ip, 'alice' ) );
		$second = $this->request();
		$second->reserve( $ip );
		$this->assertTrue( $second->record_failure( $ip, 'alice' ), 'locked at 2 failures instead of 3' );
	}

	public function test_when_the_slash_48_is_not_hot_the_normal_limit_applies(): void {
		$ip = '2001:db8:5:99::7';
		for ( $i = 1; $i <= 2; $i++ ) {
			$guard = $this->request();
			$guard->reserve( $ip );
			$this->assertFalse( $guard->record_failure( $ip, 'alice' ) );
		}
	}

	public function test_a_locked_out_client_is_not_counted_toward_the_slash_48(): void {
		$ip = '2001:db8:5:1::1';
		for ( $i = 0; $i < 3; $i++ ) {
			$guard = $this->request();
			$guard->reserve( $ip );
			$guard->record_failure( $ip, 'alice' );
		}
		$wide   = (string) LoginGuard::wide_key( $ip );
		$before = $this->counter->get( $wide );
		$guard  = $this->request();
		$this->assertSame( 0, $guard->reserve( $ip ), 'locked out: nothing reserved' );
		$this->assertSame( $before, $this->counter->get( $wide ) );
	}

	public function test_success_gives_back_the_wide_count_too(): void {
		$guard = $this->request();
		$guard->reserve( '2001:db8:5:1::1' );
		$guard->release( '2001:db8:5:1::1' );
		$this->assertSame( 0, $this->counter->get( (string) LoginGuard::wide_key( '2001:db8:5:1::1' ) ) );
	}

	public function test_ipv4_has_no_wide_key(): void {
		$this->assertNull( LoginGuard::wide_key( self::IP ) );
		$this->assertNull( LoginGuard::wide_key( '::ffff:203.0.113.10' ) );
	}
}
