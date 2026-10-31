<?php
namespace WPBouncer\Tests\Unit\ThreatMap;

use PHPUnit\Framework\TestCase;
use WPBouncer\ThreatMap\KeyIndex;

final class KeyIndexTest extends TestCase {

	private function name( int $i ): string {
		return 'wpb_map_' . substr( hash( 'sha256', (string) $i ), 0, 20 );
	}

	public function test_hundred_inserts_leave_twenty_and_evict_the_oldest(): void {
		$index   = KeyIndex::normalise( false );
		$evicted = array();
		for ( $i = 0; $i < 100; $i++ ) {
			$r       = KeyIndex::remember( $index, $this->name( $i ), 1000 + $i );
			$index   = $r['index'];
			$evicted = array_merge( $evicted, $r['evicted'] );
		}
		$this->assertCount( 20, $index['keys'] );
		$this->assertCount( 80, $evicted );
		$this->assertSame( $this->name( 0 ), $evicted[0] );
		$this->assertArrayHasKey( $this->name( 99 ), $index['keys'] );
		$this->assertArrayNotHasKey( $this->name( 79 ), $index['keys'] );
	}

	public function test_junk_and_foreign_names_are_dropped(): void {
		$n = KeyIndex::normalise(
			array(
				'gen'  => 4,
				'keys' => array(
					$this->name( 1 )               => 5,
					'wpb_map_lock'                 => 5,
					'other_transient'              => 5,
					'wpb_map_ZZZZZZZZZZZZZZZZZZZZ' => 5,
					$this->name( 2 )               => 'x',
				),
			)
		);
		$this->assertSame( 4, $n['gen'] );
		$this->assertSame( array( $this->name( 1 ) ), array_keys( $n['keys'] ) );
		$this->assertSame(
			array(
				'gen'  => 0,
				'keys' => array(),
			),
			KeyIndex::normalise( 'junk' )
		);
		$r = KeyIndex::remember( $n, 'evil', 1 );
		$this->assertSame( $n, $r['index'] );
	}

	public function test_flushed_bumps_the_generation(): void {
		$f = KeyIndex::flushed(
			array(
				'gen'  => 4,
				'keys' => array( $this->name( 1 ) => 1 ),
			)
		);
		$this->assertSame(
			array(
				'gen'  => 5,
				'keys' => array(),
			),
			$f
		);
	}
}
