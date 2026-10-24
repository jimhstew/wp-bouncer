<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use WPBouncer\Rules\RateLimitRule;
use WPBouncer\Tests\Support\MemoryStore;
use WPBouncer\Tests\Support\FrozenClock;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Rules\RateLimitRule
 */
final class RateLimitRuleTest extends TestCase {

	private FrozenClock $clock;
	private RateLimitRule $rule;

	protected function setUp(): void {
		$this->clock = new FrozenClock();
		$this->rule  = new RateLimitRule(
			array(
				'enabled'        => true,
				'max_requests'   => 5,
				'window_seconds' => 10,
				'ban_minutes'    => 2,
			),
			new MemoryStore( $this->clock )
		);
	}

	private function hit( string $ip = '203.0.113.10', bool $trusted = false ) {
		return $this->rule->inspect( Requests::make( array( 'ip' => $ip, 'trusted' => $trusted ) ) );
	}

	public function test_allows_up_to_the_limit_then_bans(): void {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertNull( $this->hit(), "request {$i}" );
		}
		$verdict = $this->hit();
		$this->assertNotNull( $verdict );
		$this->assertSame( 429, $verdict->status() );
		$this->assertSame( 120, $verdict->retry_after() );
	}

	public function test_ban_persists_after_window_and_expires(): void {
		for ( $i = 0; $i < 6; $i++ ) {
			$this->hit();
		}
		$this->clock->advance( 60 );
		$this->assertNotNull( $this->hit(), 'still banned' );
		$this->clock->advance( 60 );
		$this->assertNull( $this->hit(), 'ban expired' );
	}

	public function test_counter_resets_each_window(): void {
		for ( $i = 0; $i < 5; $i++ ) {
			$this->hit();
		}
		$this->clock->advance( 10 );
		$this->assertNull( $this->hit() );
	}

	public function test_ips_are_independent(): void {
		for ( $i = 0; $i < 6; $i++ ) {
			$this->hit();
		}
		$this->assertNull( $this->hit( '198.51.100.1' ) );
	}

	public function test_trusted_users_are_never_limited(): void {
		for ( $i = 0; $i < 50; $i++ ) {
			$this->assertNull( $this->hit( '203.0.113.10', true ) );
		}
	}

	public function test_nothing_is_counted_or_banned_for_a_client_that_cannot_be_banned(): void {
		for ( $i = 0; $i < 20; $i++ ) {
			$this->assertNull( $this->rule->inspect( Requests::make( array( 'ip' => '127.0.0.1', 'bannable' => false ) ) ) );
		}
		$this->assertNull( $this->hit( '127.0.0.1' ), 'no counter or ban was kept' );
	}

	/** NEW-5: requests with a refused forwarded header are counted under their own subject. */
	public function test_a_subject_is_counted_and_banned_instead_of_the_ip(): void {
		$make = static function () {
			return Requests::make( array( 'ip' => '127.0.0.1', 'subject' => 'rejected:127.0.0.1' ) );
		};
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertNull( $this->rule->inspect( $make() ) );
		}
		$this->assertNotNull( $this->rule->inspect( $make() ), 'the sixth is over the limit' );
		$this->assertNull( $this->rule->inspect( Requests::make( array( 'ip' => '127.0.0.1', 'bannable' => false ) ) ), 'the proxy itself is untouched' );
	}

	public function test_an_unlisted_public_peer_with_a_forwarded_header_is_still_throttled(): void {
		$resolver = new \WPBouncer\Firewall\IpResolver( 'x_forwarded_for', array( '198.51.100.1' ) );
		$server   = array( 'REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '203.0.113.99' );
		$ip       = $resolver->resolve( $server );
		$bannable = \WPBouncer\Support\IpUtils::is_bannable( $ip, $resolver->proxies(), $resolver->suspends_bans( $server ) );
		$last     = null;
		for ( $i = 0; $i < 6; $i++ ) {
			$last = $this->rule->inspect( Requests::make( array( 'ip' => $ip, 'bannable' => $bannable, 'server' => $server ) ) );
		}
		$this->assertNotNull( $last );
	}
}
