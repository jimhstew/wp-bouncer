<?php
namespace WPBouncer\Tests\Unit\ThreatMap;

use PHPUnit\Framework\TestCase;
use WPBouncer\ThreatMap\CountryTally;
use WPBouncer\ThreatMap\MapModel;

final class MapModelTest extends TestCase {

	public static function point( string $code ): ?array {
		return in_array( $code, array( 'US', 'DE', 'FR' ), true ) ? array( 100.5, 200.5 ) : null;
	}

	public function test_dots_unplaced_and_totals(): void {
		$t = CountryTally::from_rows(
			array(
				'US' => 100,
				'DE' => 4,
				'T1' => 50,
				'AQ' => 2,
				''   => 6,
			)
		);
		$m = MapModel::build( $t, array( self::class, 'point' ) );
		$this->assertSame( array( 'US', 'DE' ), array_column( $m['dots'], 'code' ) );
		$this->assertSame(
			array(
				'T1' => 50,
				'AQ' => 2,
			),
			$m['unplaced']
		);
		$this->assertSame( 4, $m['min'], 'min and max cover the dots only' );
		$this->assertSame( 100, $m['max'] );
		$this->assertSame( 7, $m['dots'][0]['bucket'] );
		$this->assertSame( 0, $m['dots'][1]['bucket'] );
		$this->assertSame( 6, $m['unknown'] );
		$this->assertSame( 162, $m['total'] );
		$this->assertSame( 104, $m['plotted_total'] );
	}

	public function test_real_centroids_place_us_and_not_aq(): void {
		$m = MapModel::build(
			CountryTally::from_rows(
				array(
					'US' => 1,
					'AQ' => 1,
					'EU' => 1,
				)
			)
		);
		$this->assertSame( array( 'US' ), array_column( $m['dots'], 'code' ) );
		$this->assertArrayHasKey( 'AQ', $m['unplaced'] );
		$this->assertArrayHasKey( 'EU', $m['unplaced'] );
	}

	public function test_states(): void {
		$some = CountryTally::from_rows( array( 'US' => 1 ) );
		$unk  = CountryTally::from_rows( array( '' => 3 ) );
		$none = CountryTally::from_rows( array() );
		$this->assertSame( 'filtered_out', MapModel::state( false, 'ok', null, true ) );
		$this->assertSame( 'busy', MapModel::state( true, 'busy', null, true ) );
		$this->assertSame( 'error', MapModel::state( true, 'error', null, true ) );
		$this->assertSame( 'empty', MapModel::state( true, 'ok', $none, false ) );
		$this->assertSame( 'no_geo', MapModel::state( true, 'ok', $unk, false ) );
		$this->assertSame( 'ok', MapModel::state( true, 'ok', $unk, true ) );
		$this->assertSame( 'ok', MapModel::state( true, 'ok', $some, false ), 'header-only countries still draw the map' );
	}
}
