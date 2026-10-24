<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Firewall;

use PHPUnit\Framework\TestCase;
use WPBouncer\Firewall\IpResolver;

/**
 * @covers \WPBouncer\Firewall\IpResolver
 */
final class IpResolverTest extends TestCase {

	public function test_remote_addr_ignores_headers(): void {
		$resolver = new IpResolver( 'remote_addr' );
		$this->assertSame(
			'198.51.100.1',
			$resolver->resolve(
				array(
					'REMOTE_ADDR'          => '198.51.100.1',
					'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
				)
			)
		);
	}

	public function test_invalid_remote_addr_returns_empty(): void {
		$this->assertSame( '', ( new IpResolver() )->resolve( array( 'REMOTE_ADDR' => 'garbage' ) ) );
		$this->assertSame( '', ( new IpResolver() )->resolve( array() ) );
	}

	public function test_unknown_source_falls_back_to_remote_addr(): void {
		$resolver = new IpResolver( 'something_else' );
		$this->assertSame( '198.51.100.1', $resolver->resolve( array( 'REMOTE_ADDR' => '198.51.100.1', 'HTTP_X_REAL_IP' => '1.2.3.4' ) ) );
	}

	public function test_cloudflare_header_from_trusted_proxy(): void {
		$resolver = new IpResolver( 'cf_connecting_ip', array( '173.245.48.0/20' ) );
		$this->assertSame(
			'203.0.113.9',
			$resolver->resolve(
				array(
					'REMOTE_ADDR'           => '173.245.48.5',
					'HTTP_CF_CONNECTING_IP' => '203.0.113.9',
				)
			)
		);
	}

	public function test_header_from_untrusted_source_is_ignored(): void {
		$resolver = new IpResolver( 'cf_connecting_ip', array( '173.245.48.0/20' ) );
		$this->assertSame(
			'192.0.2.66',
			$resolver->resolve(
				array(
					'REMOTE_ADDR'           => '192.0.2.66',
					'HTTP_CF_CONNECTING_IP' => '127.0.0.1',
				)
			),
			'a client talking to the origin directly must not be able to spoof its IP'
		);
	}

	public function test_invalid_header_falls_back(): void {
		$resolver = new IpResolver( 'x_real_ip' );
		$this->assertSame( '10.0.0.1', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_REAL_IP' => 'not-an-ip' ) ) );
		$this->assertSame( '10.0.0.1', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.1' ) ) );
	}

	public function test_forwarded_for_picks_rightmost_untrusted_hop(): void {
		$resolver = new IpResolver( 'x_forwarded_for', array( '10.0.0.0/8' ) );
		// Client forged "6.6.6.6"; the real client is 203.0.113.9, added by our proxy chain.
		$this->assertSame(
			'203.0.113.9',
			$resolver->resolve(
				array(
					'REMOTE_ADDR'          => '10.0.0.2',
					'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.9, 10.0.0.1',
				)
			)
		);
	}

	public function test_forwarded_for_with_junk_falls_back(): void {
		$resolver = new IpResolver( 'x_forwarded_for', array( '10.0.0.0/8' ) );
		$this->assertSame( '10.0.0.2', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => 'unknown' ) ) );
	}

	/** @return array<string, array{0: string}> */
	public static function header_sources(): array {
		return array(
			'x_real_ip'        => array( 'x_real_ip', 'HTTP_X_REAL_IP' ),
			'x_forwarded_for'  => array( 'x_forwarded_for', 'HTTP_X_FORWARDED_FOR' ),
			'cf_connecting_ip' => array( 'cf_connecting_ip', 'HTTP_CF_CONNECTING_IP' ),
		);
	}

	/** @return array<string, array{0: string}> */
	public static function unusable_values(): array {
		return array(
			'loopback v4'           => array( '127.0.0.1' ),
			'loopback v6'           => array( '::1' ),
			'mapped loopback'       => array( '::ffff:127.0.0.1' ),
			'unspecified v4'        => array( '0.0.0.0' ),
			'unspecified v6'        => array( '::' ),
			'private 10/8'          => array( '10.0.0.1' ),
			'private 172.16/12'     => array( '172.16.5.5' ),
			'private 192.168/16'    => array( '192.168.1.1' ),
			'link-local'            => array( '169.254.1.1' ),
			'cgnat'                 => array( '100.64.0.1' ),
			'unique local v6'       => array( 'fd00::1' ),
			'link-local v6'         => array( 'fe80::1' ),
			'mapped private'        => array( '::ffff:10.0.0.1' ),
		);
	}

	/**
	 * RT-03: with a header source and no trusted proxies, the header is ignored.
	 *
	 * @dataProvider header_sources
	 */
	public function test_header_is_ignored_when_no_trusted_proxies_are_configured( string $source, string $key ): void {
		$resolver = new IpResolver( $source );
		$this->assertTrue( $resolver->fallback_active() );
		$this->assertSame( '198.51.100.7', $resolver->resolve( array( 'REMOTE_ADDR' => '198.51.100.7', $key => '203.0.113.9' ) ) );
	}

	/**
	 * @dataProvider header_sources
	 */
	public function test_header_is_ignored_when_remote_addr_is_not_a_listed_proxy( string $source, string $key ): void {
		$resolver = new IpResolver( $source, array( '192.0.2.0/24' ) );
		$this->assertFalse( $resolver->fallback_active() );
		$this->assertSame( '198.51.100.7', $resolver->resolve( array( 'REMOTE_ADDR' => '198.51.100.7', $key => '203.0.113.9' ) ) );
	}

	/**
	 * @dataProvider unusable_values
	 */
	public function test_non_public_header_values_resolve_to_remote_addr( string $value ): void {
		foreach ( self::header_sources() as $case ) {
			$resolver = new IpResolver( $case[0], array( '192.0.2.5' ) );
			$this->assertSame( '192.0.2.5', $resolver->resolve( array( 'REMOTE_ADDR' => '192.0.2.5', $case[1] => $value ) ), $case[0] . ' ' . $value );
		}
	}

	/**
	 * @dataProvider header_sources
	 */
	public function test_public_client_from_a_trusted_proxy_is_used( string $source, string $key ): void {
		$resolver = new IpResolver( $source, array( '192.0.2.5' ) );
		$this->assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '192.0.2.5', $key => '203.0.113.5' ) ) );
	}

	public function test_forwarded_for_skips_a_loopback_hop_added_by_a_same_host_proxy(): void {
		$resolver = new IpResolver( 'x_forwarded_for', array( '127.0.0.1' ) );
		$this->assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '127.0.0.1, 203.0.113.5' ) ) );
		$this->assertSame( '203.0.113.5', $resolver->resolve( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5, 127.0.0.1' ) ) );
	}

	public function test_forwarded_for_with_a_private_last_hop_resolves_to_remote_addr(): void {
		$resolver = new IpResolver( 'x_forwarded_for', array( '127.0.0.1' ) );
		$this->assertSame( '127.0.0.1', $resolver->resolve( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5, 10.0.0.9' ) ) );
	}

	/** RT-24: a catch-all proxy entry must not turn the header back on for everyone. */
	public function test_over_broad_proxy_entries_are_ignored(): void {
		foreach ( array( '0.0.0.0/0', '::/0', '10.0.0.0/7', '2000::/15' ) as $broad ) {
			$resolver = new IpResolver( 'x_real_ip', array( $broad ) );
			$this->assertSame( array(), $resolver->proxies(), $broad );
			$this->assertTrue( $resolver->fallback_active(), $broad );
			$this->assertSame( '198.51.100.7', $resolver->resolve( array( 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_X_REAL_IP' => '203.0.113.9' ) ), $broad );
		}
	}

	public function test_narrow_entries_next_to_a_broad_one_still_count(): void {
		$resolver = new IpResolver( 'x_real_ip', array( '0.0.0.0/0', '10.0.0.0/8' ) );
		$this->assertSame( array( '10.0.0.0/8' ), $resolver->proxies() );
		$this->assertFalse( $resolver->fallback_active() );
		$this->assertSame( '203.0.113.9', $resolver->resolve( array( 'REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_REAL_IP' => '203.0.113.9' ) ) );
	}

	public function test_remote_addr_source_is_never_in_fallback(): void {
		$this->assertFalse( ( new IpResolver( 'remote_addr' ) )->fallback_active() );
	}

	/** Q2: the opt-in constant allows private client IPs from a trusted proxy, but never loopback. */
	public function test_allow_private_accepts_private_but_not_loopback_or_unspecified(): void {
		$resolver = new IpResolver( 'x_real_ip', array( '192.0.2.5' ), true );
		$server   = array( 'REMOTE_ADDR' => '192.0.2.5' );
		$this->assertSame( '10.0.0.1', $resolver->resolve( $server + array( 'HTTP_X_REAL_IP' => '10.0.0.1' ) ) );
		$this->assertSame( '192.168.1.20', $resolver->resolve( $server + array( 'HTTP_X_REAL_IP' => '192.168.1.20' ) ) );
		foreach ( array( '127.0.0.1', '::1', '::ffff:127.0.0.1', '0.0.0.0', '::' ) as $value ) {
			$this->assertSame( '192.0.2.5', $resolver->resolve( $server + array( 'HTTP_X_REAL_IP' => $value ) ), $value );
		}
	}

	public function test_allow_private_still_needs_a_trusted_proxy(): void {
		$resolver = new IpResolver( 'x_real_ip', array(), true );
		$this->assertSame( '198.51.100.7', $resolver->resolve( array( 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_X_REAL_IP' => '10.0.0.1' ) ) );
	}

	/** RT-04 */
	public function test_is_local_request(): void {
		$r = new IpResolver();
		$this->assertTrue( $r->is_local_request( array( 'REMOTE_ADDR' => '127.0.0.1' ) ) );
		$this->assertTrue( $r->is_local_request( array( 'REMOTE_ADDR' => '::1' ) ) );
		$this->assertTrue( $r->is_local_request( array( 'REMOTE_ADDR' => '::ffff:127.0.0.1' ) ) );
		$this->assertFalse( $r->is_local_request( array( 'REMOTE_ADDR' => '198.51.100.7' ) ) );
		$this->assertFalse( $r->is_local_request( array( 'REMOTE_ADDR' => '10.0.0.1' ) ), 'private is not loopback' );
		$this->assertFalse( $r->is_local_request( array() ) );
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_FORWARDED' ) as $header ) {
			$this->assertFalse( $r->is_local_request( array( 'REMOTE_ADDR' => '127.0.0.1', $header => '203.0.113.5' ) ), $header );
		}
		// Whatever the configured source.
		$this->assertFalse( ( new IpResolver( 'x_real_ip', array( '127.0.0.1' ) ) )->is_local_request( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.5' ) ) );
	}

	/** NEW-3d / R1: a forwarding header from an unlisted peer that is not public (same host or LAN) suspends bans. */
	public function test_bans_are_suspended_for_a_forwarding_header_from_an_unlisted_private_peer(): void {
		$resolver = new IpResolver( 'x_real_ip', array( '198.51.100.1' ) );
		$this->assertTrue( $resolver->suspends_bans( array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.5' ) ) );
		$this->assertTrue( $resolver->suspends_bans( array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5' ) ) );
		$this->assertTrue( $resolver->suspends_bans( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.5' ) ) );
		$this->assertFalse( $resolver->suspends_bans( array( 'REMOTE_ADDR' => '10.0.0.5' ) ), 'a direct visit' );
		$this->assertFalse( $resolver->suspends_bans( array( 'REMOTE_ADDR' => '198.51.100.1', 'HTTP_X_REAL_IP' => '203.0.113.5' ) ), 'listed proxy' );
		$this->assertFalse( ( new IpResolver( 'remote_addr' ) )->suspends_bans( array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.5' ) ) );
		$this->assertTrue( ( new IpResolver( 'x_real_ip' ) )->suspends_bans( array( 'REMOTE_ADDR' => '198.51.100.2' ) ), 'fallback' );
	}

	/** R1: anyone reaching the origin directly can add a header, so a public peer must stay bannable. */
	public function test_an_unlisted_public_peer_stays_bannable_whatever_headers_it_sends(): void {
		$resolver = new IpResolver( 'x_forwarded_for', array( '198.51.100.1' ) );
		$server   = array( 'REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '203.0.113.99' );
		$ip       = $resolver->resolve( $server );
		$this->assertSame( '203.0.113.7', $ip, 'keyed on its own address' );
		$this->assertFalse( $resolver->suspends_bans( $server ) );
		$this->assertTrue( \WPBouncer\Support\IpUtils::is_bannable( $ip, $resolver->proxies(), $resolver->suspends_bans( $server ) ) );
	}

	public function test_an_unlisted_private_peer_is_not_bannable(): void {
		$resolver = new IpResolver( 'x_real_ip', array( '198.51.100.1' ) );
		$server   = array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_REAL_IP' => '203.0.113.5' );
		$ip       = $resolver->resolve( $server );
		$this->assertFalse( \WPBouncer\Support\IpUtils::is_bannable( $ip, $resolver->proxies(), $resolver->suspends_bans( $server ) ) );
	}

	/** NEW-5 */
	public function test_a_refused_header_from_a_trusted_proxy_gets_its_own_subject(): void {
		$resolver = new IpResolver( 'x_real_ip', array( '127.0.0.1' ) );
		$this->assertSame( 'rejected:127.0.0.1', $resolver->rejected_subject( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '10.0.0.1' ) ) );
		$this->assertSame( 'rejected:127.0.0.1', $resolver->rejected_subject( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => 'junk' ) ) );
		$this->assertSame( '', $resolver->rejected_subject( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.5' ) ), 'accepted' );
		$this->assertSame( '', $resolver->rejected_subject( array( 'REMOTE_ADDR' => '127.0.0.1' ) ), 'no header' );
		$this->assertSame( '', $resolver->rejected_subject( array( 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_REAL_IP' => '10.0.0.1' ) ), 'untrusted peer' );
		$this->assertSame( '', ( new IpResolver( 'x_real_ip' ) )->rejected_subject( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '10.0.0.1' ) ), 'fallback' );
		$this->assertSame( '', ( new IpResolver( 'remote_addr' ) )->rejected_subject( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '10.0.0.1' ) ) );
	}
}
