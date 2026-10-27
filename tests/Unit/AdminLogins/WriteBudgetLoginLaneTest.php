<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\AdminLogins;

use PHPUnit\Framework\TestCase;
use WPBouncer\Log\BlockLog;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Log\BudgetedBlockLog;
use WPBouncer\Log\WriteBudget;
use WPBouncer\Tests\Support\FrozenClock;
use WPBouncer\Tests\Support\MemoryBlockLog;
use WPBouncer\Tests\Support\MemoryStore;

/**
 * The login lane of the write budget (WPB-13, SB13-09).
 *
 * @covers \WPBouncer\Log\WriteBudget
 * @covers \WPBouncer\Log\BudgetedBlockLog
 * @covers \WPBouncer\Log\BlockLog::NON_THREAT_ACTIONS
 */
final class WriteBudgetLoginLaneTest extends TestCase {

	private FrozenClock $clock;
	private MemoryStore $store;
	private MemoryBlockLog $inner;
	private BudgetedBlockLog $log;

	protected function setUp(): void {
		$this->clock = new FrozenClock();
		$this->store = new MemoryStore( $this->clock );
		$this->inner = new MemoryBlockLog();
		$this->log   = new BudgetedBlockLog( $this->inner, new WriteBudget( $this->store, $this->clock, 500 ) );
	}

	private function login(): array {
		return array( 'ip' => '203.0.113.9', 'rule' => 'admin_login', 'action' => 'login', 'reason' => 'User ID 1: a — interactive password' );
	}

	private function suppressed(): array {
		return array_values( array_filter( $this->inner->entries, static fn( $e ) => BlockLogInterface::ACTION_SUPPRESSED === $e['action'] ) );
	}

	public function test_lane_selection(): void {
		$this->assertSame( WriteBudget::LANE_LOGIN, WriteBudget::lane( $this->login() ) );
		$this->assertSame( WriteBudget::LANE_NORMAL, WriteBudget::lane( array( 'rule' => 'waf', 'action' => 'blocked' ) ) );
		$this->assertSame( WriteBudget::LANE_PRIORITY, WriteBudget::lane( array( 'rule' => 'login_lockout', 'action' => 'lockout' ) ) );
		$this->assertSame( WriteBudget::LANE_LOGIN, WriteBudget::lane( array( 'action' => 'login', 'rule' => 'login_lockout' ) ), 'the action decides first' );
		$this->assertSame( WriteBudget::LANE_NORMAL, WriteBudget::lane( array() ) );
	}

	public function test_a_login_still_records_after_the_normal_allowance_is_used_up(): void {
		for ( $i = 0; $i < 600; $i++ ) {
			$this->log->record( array( 'ip' => '10.0.0.' . ( $i % 250 + 1 ), 'rule' => 'flood', 'action' => 'blocked' ) );
		}
		$before = count( $this->inner->entries );
		$this->assertSame( 500, $before );
		$this->assertGreaterThan( 0, $this->log->record( $this->login() ) );
		$this->assertCount( $before + 1, $this->inner->entries );
	}

	public function test_25_logins_in_a_minute_give_20_rows_and_admin_login_5_in_the_summary(): void {
		for ( $i = 0; $i < 25; $i++ ) {
			$this->log->record( $this->login() );
		}
		$this->assertCount( 20, $this->inner->entries );
		$this->clock->advance( 60 );
		$this->log->record( $this->login() );
		$summary = $this->suppressed();
		$this->assertCount( 1, $summary );
		$this->assertStringContainsString( '5 further events suppressed', $summary[0]['reason'] );
		$this->assertStringContainsString( 'admin_login 5', $summary[0]['reason'] );
	}

	public function test_logins_do_not_use_the_normal_or_priority_allowance(): void {
		$budget = new WriteBudget( $this->store, $this->clock, 3, 5, 5 );
		for ( $i = 0; $i < 10; $i++ ) {
			$budget->consume_lane( 'admin_login', WriteBudget::LANE_LOGIN );
		}
		$this->assertTrue( $budget->consume( 'x' ), 'normal untouched' );
		$this->assertTrue( $budget->consume( 'x', true ), 'priority untouched' );
		$this->assertTrue( $budget->peek( 'x' ) );
	}

	public function test_blocking_rows_cannot_starve_logins_and_logins_cannot_starve_blocks(): void {
		$budget = new WriteBudget( $this->store, $this->clock, 5, 5, 5 );
		for ( $i = 0; $i < 20; $i++ ) {
			$budget->consume( 'flood' );
		}
		$this->assertTrue( $budget->consume_lane( 'admin_login', WriteBudget::LANE_LOGIN ) );
		for ( $i = 0; $i < 20; $i++ ) {
			$budget->consume_lane( 'admin_login', WriteBudget::LANE_LOGIN );
		}
		$this->clock->advance( 60 );
		$this->assertTrue( $budget->consume( 'flood' ) );
	}

	public function test_the_login_allowance_has_a_floor_of_5(): void {
		$budget = new WriteBudget( $this->store, $this->clock, 500, 30, 1 );
		$ok     = 0;
		for ( $i = 0; $i < 20; $i++ ) {
			$ok += $budget->consume_lane( 'admin_login', WriteBudget::LANE_LOGIN ) ? 1 : 0;
		}
		$this->assertSame( 5, $ok );
	}

	public function test_priority_behaviour_is_unchanged(): void {
		$budget = new WriteBudget( $this->store, $this->clock, 500, 30 );
		$ok     = 0;
		for ( $i = 0; $i < 40; $i++ ) {
			$ok += $budget->consume( 'login_lockout', true ) ? 1 : 0;
		}
		$this->assertSame( 30, $ok );
	}

	public function test_non_threat_actions(): void {
		$this->assertSame( array( 'alert', 'login' ), BlockLog::NON_THREAT_ACTIONS );
		$this->assertSame( 'login', BlockLogInterface::ACTION_LOGIN );
		$this->assertNotContains( 'blocked', BlockLog::NON_THREAT_ACTIONS );
		$this->assertNotContains( 'lockout', BlockLog::NON_THREAT_ACTIONS );
		$this->assertNotContains( 'monitored', BlockLog::NON_THREAT_ACTIONS );
	}
}
