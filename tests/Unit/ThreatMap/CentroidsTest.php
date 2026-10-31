<?php
declare( strict_types=1 );

namespace WPBouncer\Tests\Unit\ThreatMap;

use PHPUnit\Framework\TestCase;
use WPBouncer\Geo\Countries;
use WPBouncer\ThreatMap\Centroids;

/**
 * @covers \WPBouncer\ThreatMap\Centroids
 */
final class CentroidsTest extends TestCase {

	public function test_every_country_has_a_point_or_is_unplaced(): void {
		$all = array_keys( array_diff_key( Countries::all(), Countries::SPECIAL ) );
		$this->assertSame( array(), array_values( array_diff( $all, Centroids::codes(), Centroids::UNPLACED ) ) );
		$this->assertSame( array( 'AQ' ), Centroids::UNPLACED );
		$this->assertSame( array(), array_values( array_intersect( Centroids::codes(), Centroids::UNPLACED ) ) );
	}

	public function test_no_special_or_unknown_codes_have_points(): void {
		foreach ( Centroids::codes() as $code ) {
			$this->assertMatchesRegularExpression( '/^[A-Z]{2}$/', $code );
			$this->assertTrue( Countries::is_valid( $code ), $code );
			$this->assertArrayNotHasKey( $code, Countries::SPECIAL );
		}
	}

	public function test_points_lie_inside_the_view_box(): void {
		foreach ( Centroids::POINTS as $code => $p ) {
			$this->assertCount( 2, $p, $code );
			$this->assertGreaterThanOrEqual( 0, $p[0], $code );
			$this->assertLessThanOrEqual( Centroids::WIDTH, $p[0], $code );
			$this->assertGreaterThanOrEqual( 0, $p[1], $code );
			$this->assertLessThanOrEqual( Centroids::HEIGHT, $p[1], $code );
		}
	}

	public function test_point_lookup(): void {
		$this->assertNull( Centroids::point( 'AQ' ) );
		$this->assertNull( Centroids::point( 'T1' ) );
		$this->assertNull( Centroids::point( 'zz' ) );
		$p = Centroids::point( 'DE' );
		$this->assertIsArray( $p );
		// Sanity: the US is west of Germany and Australia is south of it.
		$this->assertLessThan( $p[0], Centroids::point( 'US' )[0] );
		$this->assertGreaterThan( $p[1], Centroids::point( 'AU' )[1] );
	}

	public function test_australia_uses_its_own_label_point_not_a_dependency(): void {
		// Ashmore and Cartier Is. (lat -12.4, y 289.2) also maps to AU; the dot must be on the mainland.
		$p = Centroids::point( 'AU' );
		$this->assertIsArray( $p );
		$this->assertEqualsWithDelta( 853.9, $p[0], 0.5 );
		$this->assertEqualsWithDelta( 331.4, $p[1], 0.5 );
	}

	public function test_height_matches_the_svg(): void {
		$svg = (string) file_get_contents( dirname( __DIR__, 3 ) . '/wp-bouncer/assets/map/world.svg' );
		$this->assertStringContainsString( 'viewBox="0 0 ' . Centroids::WIDTH . ' ' . Centroids::HEIGHT . '"', $svg );
	}
}
