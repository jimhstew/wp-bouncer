<?php
namespace WPBouncer\Tests\Unit\Log;

use PHPUnit\Framework\TestCase;
use WPBouncer\Log\DateRange;

final class DateRangeTest extends TestCase {

	private function parse( string $from, string $to, string $tz = 'UTC', string $now = '2026-10-26 12:00:00' ): DateRange {
		$zone = new \DateTimeZone( $tz );
		return DateRange::parse( $from, $to, $zone, ( new \DateTimeImmutable( $now, new \DateTimeZone( 'UTC' ) ) )->getTimestamp() );
	}

	public function test_default_is_thirty_days_ending_today(): void {
		$r = $this->parse( '', '' );
		$this->assertFalse( $r->explicit );
		$this->assertNull( $r->from );
		$this->assertSame( '2026-09-27', $r->start );
		$this->assertSame( '2026-10-26', $r->end );
		$this->assertSame( 30, $r->days() );
		$this->assertSame( '2026-09-27 00:00:00', $r->since_utc );
		$this->assertSame( '2026-10-27 00:00:00', $r->until_utc );
	}

	public function test_default_in_auckland_and_los_angeles(): void {
		// 2026-10-26 12:00 UTC is 2026-10-27 01:00 NZDT and 2026-10-26 05:00 PDT.
		$nz = $this->parse( '', '', 'Pacific/Auckland' );
		$this->assertSame( '2026-10-27', $nz->end );
		$this->assertSame( '2026-10-27 11:00:00', $nz->until_utc );
		$la = $this->parse( '', '', 'America/Los_Angeles' );
		$this->assertSame( '2026-10-26', $la->end );
		$this->assertSame( '2026-10-27 07:00:00', $la->until_utc );
	}

	public function test_window_across_a_dst_change(): void {
		// US DST ends 2026-11-01: that local day has 25 hours.
		$r = $this->parse( '2026-10-31', '2026-11-01', 'America/Los_Angeles', '2026-11-05 12:00:00' );
		$this->assertSame( '2026-10-31 07:00:00', $r->since_utc );
		$this->assertSame( '2026-11-02 08:00:00', $r->until_utc );
		$this->assertSame( 2, $r->days() );
	}

	/** @dataProvider bad_values */
	public function test_invalid_values_are_ignored( string $bad ): void {
		$r = $this->parse( $bad, '' );
		$this->assertFalse( $r->explicit );
		$this->assertSame( DateRange::NOTE_INVALID, $r->note );
		$r = $this->parse( '', $bad );
		$this->assertFalse( $r->explicit );
		$this->assertSame( DateRange::NOTE_INVALID, $r->note );
	}

	/** @return array<string, array{string}> */
	public static function bad_values(): array {
		return array(
			'short month' => array( '2026-1-01' ),
			'feb 30'      => array( '2026-02-30' ),
			'compact'     => array( '20261001' ),
			'datetime'    => array( '2026-10-01T00:00' ),
			'words'       => array( 'next monday' ),
			'year zero'   => array( '0000-01-01' ),
			'year 2101'   => array( '2101-01-01' ),
			'long'        => array( str_repeat( '9', 300 ) ),
			'nul'         => array( '%00' ),
			'trailing nl' => array( "2026-10-01\n" ),
		);
	}

	public function test_only_to_gives_thirty_days_back(): void {
		$r = $this->parse( '', '2026-10-10' );
		$this->assertTrue( $r->explicit );
		$this->assertSame( '2026-09-11', $r->start );
		$this->assertSame( '2026-10-10', $r->end );
		$this->assertSame( '2026-09-11', $r->from );
	}

	public function test_only_from_ends_today(): void {
		$r = $this->parse( '2026-10-01', '' );
		$this->assertSame( '2026-10-26', $r->end );
		$this->assertSame( 26, $r->days() );
	}

	public function test_reversed_range_is_ignored(): void {
		$r = $this->parse( '2026-10-10', '2026-10-01' );
		$this->assertFalse( $r->explicit );
		$this->assertSame( DateRange::NOTE_REVERSED, $r->note );
	}

	public function test_future_end_is_clamped_to_today(): void {
		$r = $this->parse( '2026-10-20', '2030-01-01' );
		$this->assertSame( '2026-10-26', $r->end );
		$this->assertSame( '', $r->note );
	}

	public function test_more_than_365_days_is_capped_from_the_end(): void {
		$r = $this->parse( '2024-01-01', '2026-10-01' );
		$this->assertSame( 365, $r->days() );
		$this->assertSame( '2026-10-01', $r->end );
		$this->assertSame( DateRange::NOTE_CAPPED, $r->note );
		$this->assertSame( $r->start, $r->from );
		$ok = $this->parse( '2025-10-02', '2026-10-01' );
		$this->assertSame( 365, $ok->days() );
		$this->assertSame( '', $ok->note );
	}
}
