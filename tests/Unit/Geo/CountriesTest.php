<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Geo;

use PHPUnit\Framework\TestCase;
use WPBouncer\Geo\Countries;

/**
 * @covers \WPBouncer\Geo\Countries
 */
final class CountriesTest extends TestCase {

	public function test_contains_all_iso_3166_codes(): void {
		$countries = array_diff_key( Countries::all(), Countries::SPECIAL );
		$this->assertCount( 250, $countries, 'ISO 3166-1 defines 249 alpha-2 codes, plus the user-assigned XK (Kosovo)' );
	}

	public function test_codes_are_two_uppercase_chars_and_sorted(): void {
		$codes = array_keys( array_diff_key( Countries::all(), Countries::SPECIAL ) );
		foreach ( $codes as $code ) {
			$this->assertMatchesRegularExpression( '/^[A-Z]{2}$/', $code );
		}
		$sorted = $codes;
		sort( $sorted );
		$this->assertSame( $sorted, $codes );
	}

	public function test_every_country_has_a_known_continent(): void {
		foreach ( array_keys( array_diff_key( Countries::all(), Countries::SPECIAL ) ) as $code ) {
			$this->assertArrayHasKey( Countries::continent( $code ), Countries::CONTINENTS, $code );
		}
	}

	public function test_lookup_helpers(): void {
		$this->assertSame( 'Germany', Countries::name( 'DE' ) );
		$this->assertSame( 'QQ', Countries::name( 'QQ' ) );
		$this->assertTrue( Countries::is_valid( 'US' ) );
		$this->assertTrue( Countries::is_valid( 'T1' ) );
		$this->assertFalse( Countries::is_valid( 'XX' ) );
		$this->assertFalse( Countries::is_valid( 'us' ) );
		$this->assertSame( 'EU', Countries::continent( 'FR' ) );
		$this->assertSame( '', Countries::continent( 'T1' ) );
	}
}
