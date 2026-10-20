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

	public function test_header_honoured_when_no_trusted_proxies_configured(): void {
		$resolver = new IpResolver( 'x_real_ip' );
		$this->assertSame( '203.0.113.9', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.9' ) ) );
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

	public function test_forwarded_for_without_trusted_list_takes_last_hop(): void {
		$resolver = new IpResolver( 'x_forwarded_for' );
		$this->assertSame( '203.0.113.9', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.9' ) ) );
	}

	public function test_forwarded_for_with_junk_falls_back(): void {
		$resolver = new IpResolver( 'x_forwarded_for', array( '10.0.0.0/8' ) );
		$this->assertSame( '10.0.0.2', $resolver->resolve( array( 'REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => 'unknown' ) ) );
	}
}
