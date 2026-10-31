<?php
namespace WPBouncer\Tests\Unit\ThreatMap;

use PHPUnit\Framework\TestCase;
use WPBouncer\ThreatMap\HeatScale;

final class HeatScaleTest extends TestCase {

	public function test_no_spread_is_top_bucket(): void {
		$this->assertSame( 7, HeatScale::bucket( 5, 5, 5 ) );
		$this->assertSame( 7, HeatScale::bucket( 1, 0, 0 ) );
	}

	public function test_ends_and_dominant_country(): void {
		$this->assertSame( 0, HeatScale::bucket( 1, 1, 10000 ) );
		$this->assertSame( 7, HeatScale::bucket( 10000, 1, 10000 ) );
		$this->assertSame( 4, HeatScale::bucket( 100, 1, 10000 ), 'log scale: the geometric middle is the middle bucket' );
		$this->assertSame( 0, HeatScale::bucket( 2, 1, 10000 ) );
	}

	public function test_monotonic_and_bounded(): void {
		$last = 0;
		for ( $c = 3; $c <= 900; $c += 7 ) {
			$b = HeatScale::bucket( $c, 3, 900 );
			$this->assertGreaterThanOrEqual( $last, $b );
			$this->assertTrue( $b >= 0 && $b <= 7 );
			$last = $b;
		}
		$this->assertSame( 0, HeatScale::bucket( 1, 3, 900 ), 'clamped below min' );
		$this->assertSame( 7, HeatScale::bucket( 5000, 3, 900 ), 'clamped above max' );
	}

	public function test_radius_grows_with_bucket(): void {
		$this->assertSame( 5.0, HeatScale::radius( 0 ) );
		$this->assertEqualsWithDelta( 10.25, HeatScale::radius( 7 ), 0.001 );
		$this->assertSame( HeatScale::radius( 7 ), HeatScale::radius( 99 ) );
	}
}
