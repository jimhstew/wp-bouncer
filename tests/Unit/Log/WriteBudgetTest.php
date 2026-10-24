<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Log;

use PHPUnit\Framework\TestCase;
use WPBouncer\Log\WriteBudget;
use WPBouncer\Tests\Support\FrozenClock;
use WPBouncer\Tests\Support\MemoryStore;

/**
 * @covers \WPBouncer\Log\WriteBudget
 */
final class WriteBudgetTest extends TestCase {

	private FrozenClock $clock;
	private MemoryStore $store;

	protected function setUp(): void {
		$this->clock = new FrozenClock();
		$this->store = new MemoryStore( $this->clock );
	}

	public function test_the_minute_in_progress_is_never_summarised(): void {
		$budget = new WriteBudget( $this->store, $this->clock, 2 );
		for ( $i = 0; $i < 5; $i++ ) {
			$budget->consume( 'waf' );
		}
		$this->assertNull( $budget->pending_summary() );
		$this->clock->advance( 60 );
		$summary = $budget->pending_summary();
		$this->assertSame( 3, $summary['suppressed'] );
		$this->assertSame( array( 'waf' => 3 ), $summary['rules'] );
	}

	public function test_a_summary_survives_a_quiet_gap_of_hours(): void {
		$budget = new WriteBudget( $this->store, $this->clock, 1 );
		$budget->consume( 'a' );
		$budget->consume( 'a' );
		$this->clock->advance( 20 * 3600 );
		$this->assertSame( 1, $budget->pending_summary()['suppressed'] );
		$this->assertNull( $budget->pending_summary(), 'reported once' );
	}

	public function test_the_summary_is_dropped_after_two_days(): void {
		$budget = new WriteBudget( $this->store, $this->clock, 1 );
		$budget->consume( 'a' );
		$budget->consume( 'a' );
		$this->clock->advance( 49 * 3600 );
		$this->assertNull( $budget->pending_summary() );
	}

	public function test_floors_and_separate_allowances(): void {
		$budget = new WriteBudget( $this->store, $this->clock, 3, 1 );
		$ok     = 0;
		for ( $i = 0; $i < 20; $i++ ) {
			$ok += $budget->consume( 'x', true ) ? 1 : 0;
		}
		$this->assertSame( 5, $ok, 'priority allowance has a floor of 5' );
		$this->assertTrue( $budget->consume( 'y' ), 'the main allowance is untouched' );
		$this->assertTrue( $budget->peek( 'y' ) );
		$this->assertFalse( $budget->peek( 'x', true ) );

		$tiny = new WriteBudget( $this->store, new FrozenClock( 1900000000 ), 0 );
		$this->assertTrue( $tiny->consume() );
		$this->assertFalse( $tiny->consume(), 'a zero budget is raised to 1' );
	}

	public function test_tracked_rules_are_capped(): void {
		$budget = new WriteBudget( $this->store, $this->clock, 1 );
		$budget->consume();
		for ( $i = 0; $i < 40; $i++ ) {
			$budget->consume( 'rule' . $i );
		}
		$this->clock->advance( 60 );
		$summary = $budget->pending_summary();
		$this->assertSame( 40, $summary['suppressed'] );
		$this->assertLessThanOrEqual( 17, count( $summary['rules'] ) );
	}
}
