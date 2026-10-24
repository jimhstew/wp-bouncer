<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Admin;

use PHPUnit\Framework\TestCase;
use WPBouncer\Admin\WidgetStats;
use WPBouncer\Tests\Support\FakeWidgetSource;
use WPBouncer\Tests\Support\FrozenClock;

/**
 * @covers \WPBouncer\Admin\WidgetStats
 */
final class WidgetStatsTest extends TestCase {

	private FakeWidgetSource $src;

	private FrozenClock $clock;

	protected function setUp(): void {
		$this->src   = new FakeWidgetSource();
		$this->clock = new FrozenClock( 1700000000 );
	}

	/**
	 * @param array<string, int> $values h24, h24_prev, d7, d14.
	 * @return array<string, int>
	 */
	private function counts( array $values ): array {
		return array_merge(
			array(
				'h24'      => 0,
				'h24_prev' => 0,
				'd7'       => 0,
				'd14'      => 0,
			),
			$values
		);
	}

	/** @return array<string, mixed> */
	private function build( string $mode = 'enforce', bool $disabled = false, bool $geo = true ): array {
		return ( new WidgetStats() )->build( $this->src, $this->clock, $mode, $disabled, $geo );
	}

	/** @return array<string, array<int, array{0: int, 1: int, 2: string}>> */
	public static function trends(): array {
		return array(
			'up'                 => array( 12, 5, 'up' ),
			'down'               => array( 3, 9, 'down' ),
			'same'               => array( 4, 4, 'same' ),
			'both zero'          => array( 0, 0, 'same' ),
			'new'                => array( 7, 0, 'new' ),
			'dropped to nothing' => array( 0, 7, 'down' ),
		);
	}

	/** @dataProvider trends */
	public function test_trend( int $now, int $before, string $expected ): void {
		$this->assertSame( $expected, WidgetStats::trend( $now, $before ) );
	}

	public function test_enforcing_numbers_and_trends(): void {
		$this->src->counts = array(
			'blocked' => $this->counts(
				array(
					'h24'      => 12,
					'h24_prev' => 5,
					'd7'       => 40,
					'd14'      => 100,
				)
			),
			'lockout' => $this->counts(
				array(
					'd7'  => 2,
					'd14' => 2,
				)
			),
		);
		$data              = $this->build();
		$this->assertSame( 'enforce', $data['status'] );
		$this->assertSame( 'blocked', $data['headline_action'] );
		$this->assertSame( 12, $data['h24'] );
		$this->assertSame( 5, $data['h24_prev'] );
		$this->assertSame( 'up', $data['trend24'] );
		$this->assertSame( 40, $data['d7'] );
		$this->assertSame( 60, $data['d7_prev'], 'previous 7 days = 14-day total minus the last 7 days' );
		$this->assertSame( 'down', $data['trend7'] );
		$this->assertSame(
			array(
				'monitored' => 0,
				'lockout'   => 2,
				'blocked'   => 40,
			),
			$data['secondary']
		);
		$this->assertFalse( $data['empty'] );
		$this->assertFalse( $data['rate_limited'] );
	}

	public function test_windows_are_derived_from_the_clock(): void {
		$this->build();
		$this->assertSame(
			array(
				gmdate( 'Y-m-d H:i:s', 1700000000 - 14 * 86400 ),
				gmdate( 'Y-m-d H:i:s', 1700000000 - 7 * 86400 ),
				gmdate( 'Y-m-d H:i:s', 1700000000 - 86400 ),
				gmdate( 'Y-m-d H:i:s', 1700000000 - 2 * 86400 ),
			),
			$this->src->period_args
		);
	}

	public function test_monitor_mode_uses_monitored_rows(): void {
		$this->src->counts = array(
			'blocked'   => $this->counts(
				array(
					'h24' => 9,
					'd7'  => 9,
					'd14' => 9,
				)
			),
			'monitored' => $this->counts(
				array(
					'h24' => 3,
					'd7'  => 4,
					'd14' => 4,
				)
			),
		);
		$data              = $this->build( 'monitor' );
		$this->assertSame( 'monitor', $data['status'] );
		$this->assertSame( 'monitored', $data['headline_action'] );
		$this->assertSame( 3, $data['h24'] );
		$this->assertSame( 4, $data['d7'] );
		$this->assertContains( array( 'rule', 'monitored' ), $this->src->top_calls );
		$this->assertNotContains( array( 'rule', 'blocked' ), $this->src->top_calls );
	}

	public function test_disabled_keeps_historical_numbers(): void {
		$this->src->counts = array(
			'blocked' => $this->counts(
				array(
					'd7'  => 6,
					'd14' => 6,
				)
			),
		);
		$data              = $this->build( 'enforce', true );
		$this->assertSame( 'disabled', $data['status'] );
		$this->assertSame( 'blocked', $data['headline_action'] );
		$this->assertSame( 6, $data['d7'] );
	}

	public function test_disabled_wins_over_monitor_for_the_status(): void {
		$this->assertSame( 'disabled', $this->build( 'monitor', true )['status'] );
	}

	public function test_empty_log_runs_one_query_only(): void {
		$data = $this->build();
		$this->assertTrue( $data['empty'] );
		$this->assertSame( array( 'period_counts' ), $this->src->calls );
		$this->assertSame( array(), $data['top_rules'] );
		$this->assertSame( array(), $data['recent'] );
	}

	public function test_only_alert_like_rows_leave_it_empty(): void {
		$this->src->counts = array(
			'suppressed' => $this->counts(
				array(
					'd7'  => 50,
					'd14' => 50,
				)
			),
		);
		$data              = $this->build();
		$this->assertTrue( $data['empty'] );
		$this->assertTrue( $data['rate_limited'] );
	}

	public function test_rate_limited_flag(): void {
		$this->src->counts = array(
			'blocked'    => $this->counts(
				array(
					'h24' => 1,
					'd7'  => 1,
					'd14' => 1,
				)
			),
			'suppressed' => $this->counts( array( 'd14' => 1 ) ),
		);
		$this->assertTrue( $this->build()['rate_limited'] );
	}

	public function test_cold_run_makes_five_source_calls_with_geo_and_four_without(): void {
		$this->src->counts = array( 'blocked' => $this->counts( array( 'd14' => 1 ) ) );
		$this->build();
		$this->assertCount( 5, $this->src->calls );

		$this->src->calls = array();
		$data             = $this->build( 'enforce', false, false );
		$this->assertCount( 4, $this->src->calls );
		$this->assertNull( $data['top_countries'] );
	}

	public function test_top_lists_and_recent_are_limited(): void {
		$this->src->counts = array( 'blocked' => $this->counts( array( 'd14' => 9 ) ) );
		$this->src->tops   = array(
			'rule'    => array(
				'a' => 9,
				'b' => 8,
				'c' => 7,
				'd' => 6,
				'e' => 5,
			),
			'ip'      => array(
				'203.0.113.1' => 5,
				'203.0.113.2' => 4,
				'203.0.113.3' => 3,
				'203.0.113.4' => 2,
			),
			'country' => array(
				'DE' => 4,
				'FR' => 3,
				'NL' => 2,
				'US' => 1,
			),
		);
		for ( $i = 0; $i < 9; $i++ ) {
			$this->src->rows[] = array(
				'created_at' => '2023-11-14 22:00:0' . $i,
				'ip'         => '203.0.113.' . $i,
				'rule'       => 'waf',
				'action'     => 'blocked',
			);
		}
		$data = $this->build();
		$this->assertCount( 3, $data['top_rules'] );
		$this->assertCount( 3, $data['top_ips'] );
		$this->assertCount( 3, $data['top_countries'] );
		$this->assertCount( 5, $data['recent'] );
		$this->assertSame(
			array(
				'value' => 'a',
				'count' => 9,
			),
			$data['top_rules'][0]
		);
	}

	public function test_numeric_looking_values_stay_strings(): void {
		$this->src->counts = array( 'blocked' => $this->counts( array( 'd14' => 1 ) ) );
		$this->src->tops   = array( 'rule' => array( '123' => 2 ) );
		$this->assertSame( '123', $this->build()['top_rules'][0]['value'] );
	}

	public function test_bad_country_codes_become_unknown_and_merge(): void {
		$this->src->counts = array( 'blocked' => $this->counts( array( 'd14' => 1 ) ) );
		$this->src->tops   = array(
			'country' => array(
				'<script>' => 5,
				'xx'       => 2,
				'DE'       => 4,
			),
		);
		$this->assertSame(
			array(
				array(
					'value' => '',
					'count' => 7,
				),
				array(
					'value' => 'DE',
					'count' => 4,
				),
			),
			$this->build()['top_countries']
		);
	}

	public function test_without_geo_countries_are_null_and_not_queried(): void {
		$this->src->counts = array( 'blocked' => $this->counts( array( 'd14' => 1 ) ) );
		$data              = $this->build( 'enforce', false, false );
		$this->assertNull( $data['top_countries'] );
		$this->assertNotContains( array( 'country', 'blocked' ), $this->src->top_calls );
	}

	public function test_recent_is_bounded_by_the_14_day_window(): void {
		$this->src->counts = array( 'blocked' => $this->counts( array( 'd14' => 1 ) ) );
		$this->build();
		$this->assertSame( $this->src->period_args[0], $this->src->recent_since );
	}

	public function test_window_total_adds_the_four_actions(): void {
		$this->src->counts = array(
			'blocked'    => $this->counts( array( 'd14' => 5 ) ),
			'monitored'  => $this->counts( array( 'd14' => 4 ) ),
			'lockout'    => $this->counts( array( 'd14' => 3 ) ),
			'suppressed' => $this->counts( array( 'd14' => 2 ) ),
		);
		$this->assertSame( 14, $this->build()['window_total'] );
	}
}
