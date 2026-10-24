<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Firewall;

use PHPUnit\Framework\TestCase;
use WPBouncer\Firewall\IpSetupAdvisor;

/**
 * @covers \WPBouncer\Firewall\IpSetupAdvisor
 */
final class IpSetupAdvisorTest extends TestCase {

	/**
	 * @param array<int, array<string, mixed>> $findings Findings.
	 * @return string[]
	 */
	private function codes( array $findings ): array {
		return array_column( $findings, 'code' );
	}

	public function test_header_source_without_proxies(): void {
		$out = ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_X_REAL_IP' => '203.0.113.5' ), 'x_real_ip', array() );
		$this->assertSame( array( IpSetupAdvisor::HEADER_WITHOUT_PROXIES ), $this->codes( $out ) );
		$this->assertSame( '198.51.100.7', $out[0]['peer'] );
		$this->assertSame( 'x_real_ip', $out[0]['source'] );
		$this->assertTrue( $out[0]['header_present'] );
	}

	public function test_header_source_without_proxies_notes_a_missing_header(): void {
		$out = ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '198.51.100.7' ), 'cf_connecting_ip', array() );
		$this->assertSame( array( IpSetupAdvisor::HEADER_WITHOUT_PROXIES ), $this->codes( $out ) );
		$this->assertFalse( $out[0]['header_present'] );
	}

	public function test_only_broad_proxies_count_as_no_proxies(): void {
		$out = ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '198.51.100.7' ), 'x_real_ip', array( '0.0.0.0/0' ) );
		$this->assertSame( array( IpSetupAdvisor::HEADER_WITHOUT_PROXIES, IpSetupAdvisor::BROAD_RANGES_IGNORED ), $this->codes( $out ) );
		$this->assertSame( array( '0.0.0.0/0' ), $out[1]['entries'] );
	}

	public function test_remote_addr_source_is_quiet_for_a_public_peer(): void {
		$this->assertSame( array(), ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4' ), 'remote_addr', array() ) );
	}

	public function test_loopback_peer_with_a_forwarding_header(): void {
		$out = ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.5' ), 'remote_addr', array() );
		$this->assertSame( array( IpSetupAdvisor::LOOPBACK_PEER ), $this->codes( $out ) );
		$this->assertSame( '127.0.0.1', $out[0]['peer'] );
		$this->assertSame( 'x_real_ip', $out[0]['header'] );
	}

	public function test_private_peer_with_a_forwarding_header(): void {
		$out = ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '203.0.113.5' ), 'remote_addr', array() );
		$this->assertSame( array( IpSetupAdvisor::LOOPBACK_PEER ), $this->codes( $out ) );
		$this->assertSame( 'x_forwarded_for', $out[0]['header'] );
	}

	public function test_forwarded_header_has_no_matching_source(): void {
		$out = ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '::1', 'HTTP_FORWARDED' => 'for=203.0.113.5' ), 'remote_addr', array() );
		$this->assertSame( array( IpSetupAdvisor::LOOPBACK_PEER ), $this->codes( $out ) );
		$this->assertSame( '', $out[0]['header'] );
	}

	public function test_loopback_peer_without_a_forwarding_header_is_quiet(): void {
		$this->assertSame( array(), ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '127.0.0.1' ), 'remote_addr', array() ) );
	}

	public function test_listed_proxy_is_quiet(): void {
		$this->assertSame( array(), ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_REAL_IP' => '203.0.113.5' ), 'x_real_ip', array( '127.0.0.1' ) ) );
	}

	public function test_peer_not_in_proxies(): void {
		$server = array( 'REMOTE_ADDR' => '198.51.100.7', 'HTTP_X_REAL_IP' => '203.0.113.5' );
		$out    = ( new IpSetupAdvisor() )->check( $server, 'x_real_ip', array( '192.0.2.0/24' ) );
		$this->assertSame( array( IpSetupAdvisor::PEER_NOT_IN_PROXIES ), $this->codes( $out ) );
		$this->assertSame( '198.51.100.7', $out[0]['peer'] );
		// No hint when the header did not arrive (a direct visit).
		$this->assertSame( array(), ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '198.51.100.7' ), 'x_real_ip', array( '192.0.2.0/24' ) ) );
	}

	public function test_broad_ranges_in_proxies_and_allowlist_are_named(): void {
		$out = ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '198.51.100.7' ), 'remote_addr', array( '::/0', '10.0.0.0/8' ), array( '0.0.0.0/0', '203.0.113.5' ) );
		$this->assertSame( array( IpSetupAdvisor::BROAD_RANGES_IGNORED ), $this->codes( $out ) );
		$this->assertSame( array( '::/0', '0.0.0.0/0' ), $out[0]['entries'] );
	}

	public function test_unknown_source_is_treated_as_remote_addr(): void {
		$this->assertSame( array(), ( new IpSetupAdvisor() )->check( array( 'REMOTE_ADDR' => '198.51.100.7' ), 'weird', array() ) );
	}
}
