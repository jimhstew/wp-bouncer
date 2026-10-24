<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Log;

use PHPUnit\Framework\TestCase;
use WPBouncer\Firewall\Firewall;
use WPBouncer\Firewall\Verdict;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Log\BudgetedBlockLog;
use WPBouncer\Log\WriteBudget;
use WPBouncer\Rules\RuleInterface;
use WPBouncer\Firewall\Request;
use WPBouncer\Tests\Support\FrozenClock;
use WPBouncer\Tests\Support\MemoryBlockLog;
use WPBouncer\Tests\Support\MemoryStore;
use WPBouncer\Tests\Support\RecordingResponder;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Log\WriteBudget
 * @covers \WPBouncer\Log\BudgetedBlockLog
 * @covers \WPBouncer\Firewall\Firewall
 */
final class BudgetedBlockLogTest extends TestCase {

	private const BUDGET = 20;

	private FrozenClock $clock;
	private MemoryStore $store;
	private MemoryBlockLog $inner;
	private WriteBudget $budget;
	private BudgetedBlockLog $log;

	protected function setUp(): void {
		$this->clock  = new FrozenClock();
		$this->store  = new MemoryStore( $this->clock );
		$this->inner  = new MemoryBlockLog();
		$this->budget = new WriteBudget( $this->store, $this->clock, self::BUDGET );
		$this->log    = new BudgetedBlockLog( $this->inner, $this->budget );
	}

	private function firewall( bool $monitor = false ): Firewall {
		$rule = new class() implements RuleInterface {
			public function id(): string {
				return 'flood';
			}
			public function is_enabled(): bool {
				return true;
			}
			public function inspect( Request $request ): ?Verdict {
				return new Verdict( 'flood', 'nope' );
			}
		};
		return new Firewall( array( $rule ), array(), $monitor, $this->log, $this->store, null, $this->budget );
	}

	/** @return int Number of de-dup keys present for the 1,000 test IPs. */
	private function dedupe_keys(): int {
		$n = 0;
		for ( $i = 0; $i < 1000; $i++ ) {
			if ( null !== $this->store->get( 'log_seen:flood:10.0.' . intdiv( $i, 250 ) . '.' . ( $i % 250 + 1 ) ) ) {
				++$n;
			}
		}
		return $n;
	}

	private function flood( Firewall $fw, int $count ): int {
		$verdicts = 0;
		for ( $i = 0; $i < $count; $i++ ) {
			$request = Requests::make( array( 'ip' => '10.0.' . intdiv( $i, 250 ) . '.' . ( $i % 250 + 1 ) ) );
			if ( null !== $fw->handle( $request, new RecordingResponder(), 'no' ) ) {
				++$verdicts;
			}
		}
		return $verdicts;
	}

	public function test_a_thousand_distinct_ips_write_at_most_the_budget_and_every_request_gets_a_verdict(): void {
		$this->assertSame( 1000, $this->flood( $this->firewall(), 1000 ) );
		$this->assertCount( self::BUDGET, $this->inner->entries );
		$this->assertSame( self::BUDGET, $this->dedupe_keys() );
	}

	public function test_the_next_minute_writes_one_summary_row_then_the_event(): void {
		$fw = $this->firewall();
		$this->flood( $fw, 1000 );
		$this->clock->advance( 60 );

		$request = Requests::make( array( 'ip' => '10.9.9.9' ) );
		$fw->handle( $request, new RecordingResponder(), 'no' );

		$this->assertCount( self::BUDGET + 2, $this->inner->entries );
		$summary = $this->inner->entries[ self::BUDGET ];
		$this->assertSame( 'wp_bouncer', $summary['rule'] );
		$this->assertSame( BlockLogInterface::ACTION_SUPPRESSED, $summary['action'] );
		$this->assertStringContainsString( ( 1000 - self::BUDGET ) . ' further events suppressed in minute 22:13 (UTC)', $summary['reason'] );
		$this->assertSame( 'flood', $this->inner->entries[ self::BUDGET + 1 ]['rule'] );

		$this->clock->advance( 60 );
		$fw->handle( Requests::make( array( 'ip' => '10.9.9.8' ) ), new RecordingResponder(), 'no' );
		$this->assertCount( self::BUDGET + 3, $this->inner->entries, 'the summary is written once' );
	}

	public function test_summary_breaks_the_drops_down_by_rule(): void {
		foreach ( array( 'sensitive_files' => 30, 'waf' => 5 ) as $rule => $n ) {
			for ( $i = 0; $i < $n; $i++ ) {
				$this->log->record( array( 'rule' => $rule, 'action' => 'blocked' ) );
			}
		}
		$this->clock->advance( 60 );
		$this->log->flush_summary();

		$summary = end( $this->inner->entries );
		$this->assertStringContainsString( '15 further events suppressed in minute 22:13 (UTC): sensitive_files 10', $summary['reason'] );
		$this->assertStringContainsString( 'waf 5', $summary['reason'] );
	}

	public function test_lockouts_and_uploads_blocks_have_their_own_budget(): void {
		$this->flood( $this->firewall(), 100 );
		$before = count( $this->inner->entries );

		$this->assertGreaterThan( 0, $this->log->record( array( 'rule' => 'login_lockout', 'action' => 'lockout' ) ) );
		$this->assertGreaterThan( 0, $this->log->record( array( 'rule' => 'uploads_php', 'action' => 'blocked' ) ) );
		$this->assertSame( $before + 2, count( $this->inner->entries ) );
		$this->assertSame( 0, $this->log->record( array( 'rule' => 'uploads_php', 'action' => 'monitored' ) ), 'only blocked uploads rows are priority' );

		for ( $i = 0; $i < 100; $i++ ) {
			$this->log->record( array( 'rule' => 'login_lockout', 'action' => 'lockout' ) );
		}
		$this->assertSame( $before + 30, count( $this->inner->entries ), 'priority rows are capped too (30 by default)' );
	}

	public function test_a_summary_is_written_after_a_quiet_gap_and_by_flush(): void {
		$this->flood( $this->firewall(), 100 );
		$this->clock->advance( 3 * 3600 );
		$this->log->flush_summary();

		$this->assertSame( BlockLogInterface::ACTION_SUPPRESSED, end( $this->inner->entries )['action'] );
		$count = count( $this->inner->entries );
		$this->log->flush_summary();
		$this->assertCount( $count, $this->inner->entries, 'written once' );
	}

	public function test_monitor_mode_is_budgeted_the_same_way(): void {
		$this->flood( $this->firewall( true ), 100 );
		$this->assertCount( self::BUDGET, $this->inner->entries );
		$this->assertSame( BlockLogInterface::ACTION_MONITORED, $this->inner->entries[0]['action'] );
	}

	public function test_alert_rows_are_never_suppressed(): void {
		$this->flood( $this->firewall(), 100 );
		$id = $this->log->record(
			array(
				'rule'   => 'alerts',
				'action' => BlockLogInterface::ACTION_ALERT,
				'reason' => 'new admin',
			)
		);
		$this->assertGreaterThan( 0, $id );
		$this->assertSame( 'alerts', $this->inner->entries[ self::BUDGET ]['rule'] );
		$this->assertSame( 0, $this->log->record( array( 'rule' => 'x', 'action' => 'blocked' ) ) );
	}
}
