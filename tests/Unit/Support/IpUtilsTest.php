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
}
