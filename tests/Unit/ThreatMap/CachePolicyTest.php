<?php
namespace WPBouncer\Tests\Unit\ThreatMap;

use PHPUnit\Framework\TestCase;
use WPBouncer\ThreatMap\CachePolicy;

final class CachePolicyTest extends TestCase {

	/** @return array{built: int, fresh_until: int, tally: array<mixed>} */
	private function box( int $fresh_until ): array {
		return array(
			'built'       => 0,
			'fresh_until' => $fresh_until,
			'tally'       => array(),
		);
	}

	public function test_decision_table(): void {
		$fresh = $this->box( 200 );
		$stale = $this->box( 50 );
		foreach ( array( array( false, false ), array( true, false ), array( false, true ), array( true, true ) ) as $lt ) {
			$this->assertSame( 'fresh', CachePolicy::decide( $fresh, 100, $lt[0], $lt[1] ) );
		}
		$this->assertSame( 'stale', CachePolicy::decide( $stale, 100, true, false ) );
		$this->assertSame( 'stale', CachePolicy::decide( $stale, 100, false, true ) );
		$this->assertSame( 'build', CachePolicy::decide( $stale, 100, false, false ) );
		$this->assertSame( 'busy', CachePolicy::decide( null, 100, false, true ) );
		$this->assertSame( 'busy', CachePolicy::decide( null, 100, true, true ) );
		$this->assertSame( 'build', CachePolicy::decide( null, 100, false, false ) );
		$this->assertSame( 'build', CachePolicy::decide( null, 100, true, false ), 'a slow page beats an empty one' );
		$this->assertSame( 'stale', CachePolicy::decide( $this->box( 100 ), 100, true, false ), 'fresh_until is exclusive' );
	}

	public function test_ttl_is_clamped_and_flood_is_longest(): void {
		$this->assertSame( 300, CachePolicy::ttl( 300, 10 ) );
		$this->assertSame( 60, CachePolicy::ttl( 1, 10 ) );
		$this->assertSame( 3600, CachePolicy::ttl( 99999, 10 ) );
		$this->assertSame( 3600, CachePolicy::ttl( 60, CachePolicy::FLOOD_ROWS + 1 ) );
		$this->assertSame( 60, CachePolicy::ttl( 60, CachePolicy::FLOOD_ROWS ) );
	}

	public function test_box_round_trip_and_rejection(): void {
		$box = CachePolicy::make_box( 1000, 300, array( 'countries' => array() ) );
		$n   = CachePolicy::normalise_box( $box );
		$this->assertSame( 1300, $n['fresh_until'] ?? null );
		$this->assertNull( CachePolicy::normalise_box( false ) );
		$this->assertNull( CachePolicy::normalise_box( 'x' ) );
		$this->assertNull( CachePolicy::normalise_box( array( 'v' => 2 ) + $box ) );
		$this->assertNull( CachePolicy::normalise_box( array( 'built' => '1' ) + $box ) );
	}
}
