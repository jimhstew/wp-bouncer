<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use WPBouncer\Support\CounterSubject;

/**
 * @covers \WPBouncer\Support\CounterSubject
 */
final class CounterSubjectTest extends TestCase {

	public function test_ipv4_is_the_address(): void {
		$this->assertSame( '203.0.113.9', CounterSubject::of( '203.0.113.9' ) );
	}

	public function test_mapped_ipv4_shares_the_ipv4_subject(): void {
		$this->assertSame( CounterSubject::of( '1.2.3.4' ), CounterSubject::of( '::ffff:1.2.3.4' ) );
		$this->assertSame( '1.2.3.4', CounterSubject::of( '::FFFF:0102:0304' ) );
	}

	public function test_addresses_in_one_slash_64_share_a_subject(): void {
		$a = CounterSubject::of( '2001:db8:1:2::1' );
		$this->assertSame( '2001:db8:1:2::/64', $a );
		$this->assertSame( $a, CounterSubject::of( '2001:0DB8:1:2:ffff:ffff:ffff:ffff' ) );
		$this->assertSame( $a, CounterSubject::of( '2001:db8:1:2:0:0:0:5' ) );
	}

	public function test_different_slash_64s_are_independent(): void {
		$this->assertNotSame( CounterSubject::of( '2001:db8:1:2::1' ), CounterSubject::of( '2001:db8:1:3::1' ) );
	}

	public function test_prefix_can_be_widened_or_narrowed(): void {
		$this->assertSame( '2001:db8:1::/48', CounterSubject::of( '2001:db8:1:2::1', 48 ) );
		$this->assertSame( '2001:db8:1:200::/56', CounterSubject::of( '2001:db8:1:2ff::1', 56 ) );
		$this->assertSame( '2001:db8:1:2::1/128', CounterSubject::of( '2001:db8:1:2::1', 128 ) );
		$this->assertSame( '2001:db8:1:2::/63', CounterSubject::of( '2001:db8:1:3::1', 63 ) );
	}

	public function test_prefix_is_clamped(): void {
		$this->assertSame( '2001:db8::/48', CounterSubject::of( '2001:db8::1', 0 ), 'narrower than /48 is raised to /48' );
		$this->assertSame( '2001:db8::/48', CounterSubject::of( '2001:db8::1', 16 ) );
		$this->assertSame( '2001:db8::1/128', CounterSubject::of( '2001:db8::1', 500 ) );
	}

	public function test_translation_forms_use_the_embedded_ipv4(): void {
		$this->assertSame( '198.51.100.7', CounterSubject::of( '64:ff9b::198.51.100.7' ) );
		$this->assertSame( '198.51.100.7', CounterSubject::of( '64:ff9b::c633:6407' ) );
		$this->assertSame( '198.51.100.7', CounterSubject::of( '::ffff:0:198.51.100.7' ) );
		$this->assertSame( '198.51.100.7', CounterSubject::of( '2002:c633:6407::1' ) );
		$this->assertSame( '198.51.100.7', CounterSubject::of( '2002:c633:6407:5:6:7:8:9' ), 'any 6to4 host behind that IPv4' );
		$this->assertSame( '64:ff9b::/64', CounterSubject::of( '64:ff9b::127.0.0.1' ), 'a non-public embedded IPv4 stays an IPv6 key' );
		$this->assertSame( '2002:a00:1::/48', CounterSubject::of( '2002:0a00:0001::1', 48 ) );
	}

	public function test_teredo_is_keyed_as_ordinary_ipv6(): void {
		$this->assertSame( '2001:0:4136:e378::/64', CounterSubject::of( '2001:0:4136:e378:8000:63bf:3fff:fdd2' ) );
	}

	public function test_uncounted_addresses_give_an_empty_subject(): void {
		foreach ( array( '127.0.0.1', '127.9.9.9', '::1', '::ffff:127.0.0.1', '0.0.0.0', '::', '' ) as $ip ) {
			$this->assertSame( '', CounterSubject::of( $ip ), $ip );
		}
	}

	public function test_non_addresses_pass_through(): void {
		$this->assertSame( 'rejected:198.51.100.1', CounterSubject::of( 'rejected:198.51.100.1' ) );
	}

	public function test_default_prefix_without_the_constant(): void {
		$this->assertSame( 64, CounterSubject::configured_prefix() );
	}
}
