<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use WPBouncer\Support\IpUtils;

/**
 * @covers \WPBouncer\Support\IpUtils
 */
final class IpUtilsTest extends TestCase {

	/** @dataProvider validity */
	public function test_is_valid( string $ip, bool $expected ): void {
		$this->assertSame( $expected, IpUtils::is_valid( $ip ) );
	}

	public static function validity(): array {
		return array(
			'ipv4'           => array( '192.0.2.1', true ),
			'ipv6'           => array( '2001:db8::1', true ),
			'ipv4-mapped'    => array( '::ffff:192.0.2.1', true ),
			'out of range'   => array( '256.1.1.1', false ),
			'empty'          => array( '', false ),
			'hostname'       => array( 'example.com', false ),
			'cidr not an ip' => array( '10.0.0.0/8', false ),
		);
	}

	/** @dataProvider ranges */
	public function test_is_valid_range( string $entry, bool $expected ): void {
		$this->assertSame( $expected, IpUtils::is_valid_range( $entry ) );
	}

	public static function ranges(): array {
		return array(
			'single'           => array( '10.1.2.3', true ),
			'v4 cidr'          => array( '10.0.0.0/8', true ),
			'v4 /32'           => array( '10.0.0.1/32', true ),
			'v4 /33 too big'   => array( '10.0.0.0/33', false ),
			'v6 cidr'          => array( '2001:db8::/32', true ),
			'v6 /128'          => array( '2001:db8::1/128', true ),
			'v6 /129 too big'  => array( '2001:db8::/129', false ),
			'missing bits'     => array( '10.0.0.0/', false ),
			'negative bits'    => array( '10.0.0.0/-1', false ),
			'garbage'          => array( 'nope/8', false ),
			'whitespace ok'    => array( '  10.0.0.0/8 ', true ),
		);
	}

	/** @dataProvider membership */
	public function test_in_range( string $ip, string $range, bool $expected ): void {
		$this->assertSame( $expected, IpUtils::in_range( $ip, $range ) );
	}

	public static function membership(): array {
		return array(
			'exact match'              => array( '192.0.2.1', '192.0.2.1', true ),
			'exact mismatch'           => array( '192.0.2.1', '192.0.2.2', false ),
			'/24 inside'               => array( '192.0.2.200', '192.0.2.0/24', true ),
			'/24 outside'              => array( '192.0.3.1', '192.0.2.0/24', false ),
			'/0 matches all v4'        => array( '8.8.8.8', '0.0.0.0/0', true ),
			'non-byte boundary in'     => array( '10.0.0.7', '10.0.0.0/29', true ),
			'non-byte boundary out'    => array( '10.0.0.8', '10.0.0.0/29', false ),
			'/12 in'                   => array( '172.31.255.255', '172.16.0.0/12', true ),
			'/12 out'                  => array( '172.32.0.0', '172.16.0.0/12', false ),
			'v6 /32 inside'            => array( '2001:db8:abcd::1', '2001:db8::/32', true ),
			'v6 /32 outside'           => array( '2001:db9::1', '2001:db8::/32', false ),
			'v6 /127 boundary'         => array( '2001:db8::1', '2001:db8::/127', true ),
			'v4 vs v6 range'           => array( '192.0.2.1', '2001:db8::/32', false ),
			'v6 vs v4 range'           => array( '2001:db8::1', '0.0.0.0/0', false ),
			'mapped v6 equals v4'      => array( '::ffff:192.0.2.1', '192.0.2.0/24', true ),
			'invalid ip'               => array( 'bogus', '0.0.0.0/0', false ),
			'invalid range'            => array( '192.0.2.1', 'bogus', false ),
		);
	}

	public function test_matches_any(): void {
		$list = array( '10.0.0.0/8', '2001:db8::/32', '198.51.100.7' );
		$this->assertTrue( IpUtils::matches_any( '10.200.0.1', $list ) );
		$this->assertTrue( IpUtils::matches_any( '198.51.100.7', $list ) );
		$this->assertTrue( IpUtils::matches_any( '2001:db8::5', $list ) );
		$this->assertFalse( IpUtils::matches_any( '198.51.100.8', $list ) );
		$this->assertFalse( IpUtils::matches_any( '198.51.100.8', array() ) );
	}

	public function test_is_loopback(): void {
		$this->assertTrue( IpUtils::is_loopback( '127.0.0.1' ) );
		$this->assertTrue( IpUtils::is_loopback( '127.9.9.9' ) );
		$this->assertTrue( IpUtils::is_loopback( '::1' ) );
		$this->assertFalse( IpUtils::is_loopback( '10.0.0.1' ) );
	}

	public function test_hex16_encoding_orders_correctly(): void {
		$this->assertSame( '00000000000000000000ffff01020304', IpUtils::to_hex16( '1.2.3.4' ) );
		$this->assertSame( 32, strlen( (string) IpUtils::to_hex16( '2001:db8::1' ) ) );
		$this->assertNull( IpUtils::to_hex16( 'nope' ) );
		// Lexical order of the hex must match numeric order, which the geo table relies on.
		$this->assertLessThan( 0, strcmp( IpUtils::to_hex16( '9.255.255.255' ), IpUtils::to_hex16( '10.0.0.0' ) ) );
		$this->assertLessThan( 0, strcmp( IpUtils::to_hex16( '255.255.255.255' ), IpUtils::to_hex16( '2001:db8::' ) ) );
	}

	/** @dataProvider public_addresses */
	public function test_is_public( string $ip, bool $expected ): void {
		$this->assertSame( $expected, IpUtils::is_public( $ip ), $ip );
	}

	public static function public_addresses(): array {
		return array(
			'documentation 192.0.2'    => array( '192.0.2.1', true ),
			'documentation 198.51.100' => array( '198.51.100.7', true ),
			'documentation 203.0.113'  => array( '203.0.113.5', true ),
			'public v4'                => array( '8.8.8.8', true ),
			'public v6'                => array( '2001:db8::1', true ),
			'mapped public'            => array( '::ffff:203.0.113.5', true ),
			'172.32 is public'         => array( '172.32.0.1', true ),
			'100.128 is public'        => array( '100.128.0.1', true ),
			'loopback'                 => array( '127.0.0.1', false ),
			'loopback /8'              => array( '127.9.9.9', false ),
			'loopback v6'              => array( '::1', false ),
			'mapped loopback'          => array( '::ffff:127.0.0.1', false ),
			'mapped loopback hex'      => array( '::ffff:7f00:1', false ),
			'unspecified'              => array( '0.0.0.0', false ),
			'unspecified v6'           => array( '::', false ),
			'this network'             => array( '0.1.2.3', false ),
			'10/8'                     => array( '10.255.255.255', false ),
			'172.16/12'                => array( '172.31.255.255', false ),
			'192.168/16'               => array( '192.168.0.1', false ),
			'link-local'               => array( '169.254.169.254', false ),
			'cgnat'                    => array( '100.127.255.255', false ),
			'ula'                      => array( 'fc00::1', false ),
			'ula fd'                   => array( 'fdff::1', false ),
			'link-local v6'            => array( 'febf::1', false ),
			'mapped private'           => array( '::ffff:192.168.1.1', false ),
			'invalid'                  => array( 'nope', false ),
			'empty'                    => array( '', false ),
		);
	}

	public function test_canonical_unmaps_ipv4_and_normalises_ipv6(): void {
		$this->assertSame( '127.0.0.1', IpUtils::canonical( '::ffff:127.0.0.1' ) );
		$this->assertSame( '2001:db8::1', IpUtils::canonical( '2001:0db8:0000:0000:0000:0000:0000:0001' ) );
		$this->assertSame( '203.0.113.5', IpUtils::canonical( '203.0.113.5' ) );
		$this->assertSame( 'junk', IpUtils::canonical( 'junk' ) );
	}

	/** @dataProvider broad_ranges */
	public function test_is_broad_range( string $entry, bool $expected ): void {
		$this->assertSame( $expected, IpUtils::is_broad_range( $entry ), $entry );
	}

	public static function broad_ranges(): array {
		return array(
			'0.0.0.0/0'       => array( '0.0.0.0/0', true ),
			'10.0.0.0/7'      => array( '10.0.0.0/7', true ),
			'/1'              => array( '128.0.0.0/1', true ),
			'/8 is allowed'   => array( '10.0.0.0/8', false ),
			'/24'             => array( '192.0.2.0/24', false ),
			'single'          => array( '203.0.113.5', false ),
			'/32'             => array( '203.0.113.5/32', false ),
			'::/0'            => array( '::/0', true ),
			'/15 v6'          => array( '2000::/15', true ),
			'/16 v6 allowed'  => array( '2001::/16', false ),
			'/32 v6'          => array( '2001:db8::/32', false ),
			'single v6'       => array( '2001:db8::1', false ),
			'garbage'         => array( 'nope/0', false ),
			'::ffff:0:0/96'   => array( '::ffff:0:0/96', true ),
			'::/80'           => array( '::/80', true ),
			'mapped /100'     => array( '::ffff:0.0.0.0/100', true ),
			'unmasked 0:0:0:0:1::/64'  => array( '0:0:0:0:1::/64', true ),
			'unmasked ::1:0:0:0/64'    => array( '::1:0:0:0/64', true ),
			'unmasked /72'             => array( '0:0:0:0:0:1::/72', true ),
			'not in the zero block'    => array( '0:0:0:1::/80', false ),
			'mapped /104 ok'  => array( '::ffff:10.0.0.0/104', false ),
			'mapped /120 ok'  => array( '::ffff:10.1.2.0/120', false ),
		);
	}

	public function test_without_broad_keeps_order_and_narrow_entries(): void {
		$this->assertSame( array( '10.0.0.0/8', '203.0.113.5' ), IpUtils::without_broad( array( '0.0.0.0/0', '10.0.0.0/8', '::/0', '203.0.113.5' ) ) );
	}

	public function test_is_unspecified(): void {
		$this->assertTrue( IpUtils::is_unspecified( '0.0.0.0' ) );
		$this->assertTrue( IpUtils::is_unspecified( '::' ) );
		$this->assertFalse( IpUtils::is_unspecified( '127.0.0.1' ) );
		$this->assertFalse( IpUtils::is_unspecified( 'nope' ) );
	}

	public function test_is_bannable(): void {
		$proxies = array( '192.0.2.0/24', '203.0.113.77' );
		$this->assertTrue( IpUtils::is_bannable( '198.51.100.7', $proxies, false ) );
		$this->assertFalse( IpUtils::is_bannable( '127.0.0.1', array(), false ), 'loopback is never banned' );
		$this->assertFalse( IpUtils::is_bannable( '::1', array(), false ) );
		$this->assertFalse( IpUtils::is_bannable( '::ffff:127.0.0.1', array(), false ) );
		$this->assertFalse( IpUtils::is_bannable( '0.0.0.0', array(), false ) );
		$this->assertFalse( IpUtils::is_bannable( '192.0.2.9', $proxies, false ), 'trusted proxy range' );
		$this->assertFalse( IpUtils::is_bannable( '203.0.113.77', $proxies, false ), 'trusted proxy address' );
		$this->assertFalse( IpUtils::is_bannable( '', $proxies, false ) );
		$this->assertFalse( IpUtils::is_bannable( '198.51.100.7', $proxies, true ), 'suspended during the fallback' );
	}
}
