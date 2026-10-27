<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\AdminLogins;

use PHPUnit\Framework\TestCase;
use WPBouncer\AdminLogins\LocationHistory;

/**
 * @covers \WPBouncer\AdminLogins\LocationHistory
 */
final class LocationHistoryTest extends TestCase {

	/** @dataProvider junk */
	public function test_from_meta_rejects_junk( mixed $raw ): void {
		$this->assertNull( LocationHistory::from_meta( $raw ) );
	}

	public static function junk(): array {
		return array(
			'false'            => array( false ),
			'empty string'     => array( '' ),
			'string'           => array( 'x' ),
			'object'           => array( new \stdClass() ),
			'empty array'      => array( array() ),
			'no entries key'   => array( array( 'since' => 5 ) ),
			'no since'         => array( array( 'e' => array() ) ),
			'string since'     => array( array( 'since' => '5', 'e' => array() ) ),
			'zero since'       => array( array( 'since' => 0, 'e' => array() ) ),
			'negative since'   => array( array( 'since' => -3, 'e' => array() ) ),
			'entries not list' => array( array( 'since' => 5, 'e' => 'x' ) ),
		);
	}

	public function test_bad_entries_are_dropped_and_good_ones_kept(): void {
		$h = LocationHistory::from_meta(
			array(
				'since' => 100,
				'e'     => array(
					array( 'r' => '203.0.113.0/24', 'c' => 'DE', 't' => 200 ),
					array( 'r' => '203.0.113.0/16', 'c' => 'DE', 't' => 200 ),
					array( 'r' => '203.0.113.0/64', 'c' => 'DE', 't' => 200 ),
					array( 'r' => '2001:db8::/24', 'c' => 'DE', 't' => 200 ),
					array( 'r' => '<script>/24', 'c' => 'DE', 't' => 200 ),
					array( 'r' => '198.51.100.0/24', 'c' => 'germany', 't' => 200 ),
					array( 'r' => '198.51.100.0/24', 'c' => 'de', 't' => 200 ),
					array( 'r' => '198.51.100.0/24', 'c' => 'DE', 't' => '200' ),
					array( 'r' => '198.51.100.0/24', 'c' => 'DE', 't' => 0 ),
					array( 'r' => '198.51.100.0/24', 'c' => 'DE' ),
					'not an array',
					array( 'r' => '2001:db8::/64', 'c' => '', 't' => 150 ),
				),
			)
		);
		$this->assertNotNull( $h );
		$this->assertSame(
			array(
				array( 'r' => '2001:db8::/64', 'c' => '', 't' => 150 ),
				array( 'r' => '203.0.113.0/24', 'c' => 'DE', 't' => 200 ),
			),
			$h->entries(),
			'sorted by time, oldest first'
		);
	}

	public function test_stored_entries_are_limited_to_100(): void {
		$e = array();
		for ( $i = 1; $i <= 150; $i++ ) {
			$e[] = array( 'r' => '10.1.' . ( $i % 250 ) . '.0/24', 'c' => 'DE', 't' => $i );
		}
		$h = LocationHistory::from_meta( array( 'since' => 1, 'e' => $e ) );
		$this->assertLessThanOrEqual( 100, count( $h->entries() ) );
	}

	public function test_round_trip(): void {
		$h = LocationHistory::start( 1000 )->with_login( '203.0.113.0/24', 'DE', 1500, 90 * 86400, 20 );
		$again = LocationHistory::from_meta( $h->to_meta() );
		$this->assertEquals( $h, $again );
		$this->assertSame( 1000, $again->since() );
	}

	public function test_with_login_is_immutable_and_refreshes_a_range(): void {
		$h  = LocationHistory::start( 1000 )->with_login( '203.0.113.0/24', 'DE', 1500, 86400 * 90, 20 );
		$h2 = $h->with_login( '203.0.113.0/24', '', 1600, 86400 * 90, 20 );
		$this->assertSame( 1500, $h->entries()[0]['t'] );
		$this->assertSame( 1600, $h2->entries()[0]['t'] );
		$this->assertSame( 'DE', $h2->entries()[0]['c'], 'an empty country keeps the old one' );
		$h3 = $h2->with_login( '203.0.113.0/24', 'FR', 1700, 86400 * 90, 20 );
		$this->assertSame( 'FR', $h3->entries()[0]['c'], 'a non-empty country overwrites' );
		$this->assertCount( 1, $h3->entries() );
	}

	public function test_with_login_ignores_an_invalid_range(): void {
		$h = LocationHistory::start( 1000 )->with_login( 'garbage', 'DE', 1500, 86400 * 90, 20 );
		$this->assertSame( array(), $h->entries() );
	}

	public function test_pruning_keeps_since_and_the_boundary_entry(): void {
		$h = LocationHistory::start( 10 )
			->with_login( '10.0.0.0/24', 'DE', 100, 1000000, 20 )
			->with_login( '10.0.1.0/24', 'DE', 200, 1000000, 20 );
		$p = $h->pruned( 1100, 1000 );
		$this->assertCount( 2, $h->pruned( 1100, 1000 )->entries() );
		$this->assertCount( 1, $h->pruned( 1101, 1000 )->entries() );
		$empty = $h->pruned( 100000, 1000 );
		$this->assertSame( array(), $empty->entries() );
		$this->assertSame( 10, $empty->since() );
	}

	public function test_known_countries_are_unique_and_skip_empty(): void {
		$h = LocationHistory::start( 1 )
			->with_login( '10.0.0.0/24', 'DE', 100, 1000000, 20 )
			->with_login( '10.0.1.0/24', 'DE', 101, 1000000, 20 )
			->with_login( '10.0.2.0/24', '', 102, 1000000, 20 )
			->with_login( '10.0.3.0/24', 'FR', 103, 1000000, 20 );
		$this->assertSame( array( 'DE', 'FR' ), $h->known_countries() );
	}
}
