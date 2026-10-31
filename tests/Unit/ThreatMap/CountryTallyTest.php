<?php
namespace WPBouncer\Tests\Unit\ThreatMap;

use PHPUnit\Framework\TestCase;
use WPBouncer\ThreatMap\CountryTally;

final class CountryTallyTest extends TestCase {

	public function test_case_is_merged_and_junk_is_unknown(): void {
		$t = CountryTally::from_rows(
			array(
				'us'       => 2,
				'US'       => 3,
				''         => 4,
				'<script>' => 1,
				'ZZ'       => 2,
				'T1'       => 5,
				' de '     => 1,
			)
		);
		$this->assertSame(
			array(
				'T1' => 5,
				'US' => 5,
				'DE' => 1,
			),
			$t->countries()
		);
		$this->assertSame( 7, $t->unknown() );
		$this->assertSame( 18, $t->total() );
	}

	public function test_order_is_count_then_code(): void {
		$t = CountryTally::from_rows(
			array(
				'FR' => 2,
				'DE' => 2,
				'US' => 9,
			)
		);
		$this->assertSame( array( 'US', 'DE', 'FR' ), array_keys( $t->countries() ) );
	}

	public function test_numeric_keys_do_not_break(): void {
		$t = CountryTally::from_rows( array( '12' => 3 ) );
		$this->assertSame( 3, $t->unknown() );
	}

	public function test_round_trip_and_revalidation(): void {
		$t = CountryTally::from_rows(
			array(
				'US' => 2,
				'x'  => 1,
			)
		);
		$this->assertSame( $t->to_array(), CountryTally::from_array( $t->to_array() )->to_array() );
		$bad = CountryTally::from_array(
			array(
				'countries' => array(
					'"><img' => 4,
					'DE'     => 2,
					'FR'     => 'x',
				),
				'unknown'   => 1,
			)
		);
		$this->assertSame( array( 'DE' => 2 ), $bad->countries() );
		$this->assertSame( 5, $bad->unknown() );
		$this->assertSame( 0, CountryTally::from_array( 'junk' )->total() );
	}
}
