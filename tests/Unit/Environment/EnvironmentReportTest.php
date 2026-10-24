<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Environment;

use PHPUnit\Framework\TestCase;
use WPBouncer\Environment\CheckInterface;
use WPBouncer\Environment\CheckResult;
use WPBouncer\Environment\EnvironmentInterface;
use WPBouncer\Environment\EnvironmentReport;
use WPBouncer\Environment\Severity;
use WPBouncer\Environment\SupportPolicy;
use WPBouncer\Tests\Support\FakeEnvironment;
use WPBouncer\Tests\Support\FrozenClock;

/**
 * @covers \WPBouncer\Environment\EnvironmentReport
 * @covers \WPBouncer\Environment\Report
 * @covers \WPBouncer\Environment\Severity
 */
final class EnvironmentReportTest extends TestCase {

	private function check( string $id, ?callable $run = null ): CheckInterface {
		return new class( $id, $run ) implements CheckInterface {
			/** @var callable|null */
			private $run;
			public function __construct( private string $id, ?callable $run ) {
				$this->run = $run;
			}
			public function id(): string {
				return $this->id;
			}
			public function run( EnvironmentInterface $env ): CheckResult {
				return null !== $this->run ? ( $this->run )() : new CheckResult( $this->id, 'php', Severity::Info, 'T', 'V' );
			}
		};
	}

	/** @return string[] Ids in the report. */
	private function ids( EnvironmentReport $report, array $extra ): array {
		return array_map( static fn( CheckResult $r ): string => $r->id, $report->run( new FakeEnvironment(), $extra )->results() );
	}

	public function test_a_throwing_check_becomes_an_unknown_row_without_its_message(): void {
		$report = new EnvironmentReport(
			array(
				$this->check(
					'wpb_boom',
					static function () {
						throw new \RuntimeException( '/secret/path/in/message' );
					}
				),
				$this->check( 'wpb_fine' ),
			)
		);
		$result = $report->run( new FakeEnvironment() )->results();

		$this->assertCount( 2, $result );
		$this->assertSame( Severity::Unknown, $result[0]->severity );
		$this->assertSame( 'Check failed', $result[0]->value );
		$this->assertStringNotContainsString( 'secret', $result[0]->title . $result[0]->value . $result[0]->why );
		$this->assertSame( Severity::Info, $result[1]->severity );
	}

	public function test_a_check_returning_the_wrong_type_is_an_unknown_row(): void {
		$bad    = new class() implements CheckInterface {
			public function id(): string {
				return 'wpb_bad';
			}
			public function run( EnvironmentInterface $env ): CheckResult {
				return (object) array(); // @phpstan-ignore-line deliberately wrong.
			}
		};
		$result = ( new EnvironmentReport( array( $bad ) ) )->run( new FakeEnvironment() )->results();
		$this->assertSame( Severity::Unknown, $result[0]->severity );
	}

	public function test_third_party_ids_are_validated_and_cannot_shadow_built_ins(): void {
		$report = new EnvironmentReport( array( $this->check( 'wpb_builtin' ) ) );
		$extra  = array(
			$this->check( 'acme_ok' ),
			$this->check( 'ab' ),                      // Too short.
			$this->check( 'Has-Caps' ),                // Invalid characters.
			$this->check( str_repeat( 'a', 65 ) ),     // Too long.
			$this->check( 'wpb_builtin' ),             // Duplicate of a built-in.
			$this->check( 'wpb_shadow' ),              // Reserved prefix, not a built-in class.
			$this->check( 'acme_ok' ),                 // Duplicate: first wins.
			'not a check',
		);

		$this->assertSame( array( 'wpb_builtin', 'acme_ok' ), $this->ids( $report, $extra ) );
	}

	public function test_a_result_always_carries_the_checks_own_id_and_third_party_values_are_private(): void {
		$liar   = $this->check(
			'acme_liar',
			static fn() => new CheckResult( 'wpb_php_version', 'versions', Severity::Ok, 'PHP version', 'looks fine', '', '', false )
		);
		$result = ( new EnvironmentReport( array( $this->check( 'wpb_real' ) ) ) )->run( new FakeEnvironment(), array( $liar ) )->results();

		$this->assertSame( array( 'wpb_real', 'acme_liar' ), array_map( static fn( CheckResult $r ): string => $r->id, $result ) );
		$this->assertTrue( $result[1]->is_private, 'a third-party value is private by default' );
		$this->assertFalse( $result[0]->is_private );
	}

	public function test_a_wpb_id_is_only_for_the_built_in_instances(): void {
		$this->assertSame( array(), $this->ids( new EnvironmentReport( array() ), array( $this->check( 'wpb_php_version' ), $this->check( 'wpb_anything' ) ) ) );
	}

	public function test_id_is_asked_once_per_check(): void {
		$counter = new class() implements CheckInterface {
			public int $calls = 0;
			public function id(): string {
				++$this->calls;
				return 'acme_counted';
			}
			public function run( EnvironmentInterface $env ): CheckResult {
				return new CheckResult( 'acme_counted', 'php', Severity::Ok, 't', 'v' );
			}
		};
		( new EnvironmentReport( array() ) )->run( new FakeEnvironment(), array( $counter ) );

		$this->assertSame( 1, $counter->calls );
	}

	public function test_a_failed_built_in_keeps_its_real_group_so_a_version_finding_stays_a_version_finding(): void {
		$boom   = static function () {
			throw new \RuntimeException( 'x' );
		};
		$report = ( new EnvironmentReport( array( $this->check( 'wpb_php_version', $boom ), $this->check( 'wpb_debug_log', $boom ), $this->check( 'wpb_expose_php', $boom ) ) ) )->run( new FakeEnvironment() )->results();

		$this->assertSame( array( 'versions', 'wordpress', 'php' ), array_map( static fn( CheckResult $r ): string => $r->group, $report ) );
		$this->assertSame( Severity::Unknown, $report[0]->severity );
	}

	public function test_a_built_in_whose_id_throws_is_skipped_without_breaking_the_rest(): void {
		$bad = new class() implements CheckInterface {
			public function id(): string {
				throw new \RuntimeException( 'no id' );
			}
			public function run( EnvironmentInterface $env ): CheckResult {
				return new CheckResult( 'x', 'php', Severity::Ok, 't', 'v' );
			}
		};
		$ids = array_map( static fn( CheckResult $r ): string => $r->id, ( new EnvironmentReport( array( $bad, $this->check( 'wpb_fine' ) ) ) )->run( new FakeEnvironment() )->results() );

		$this->assertSame( array( 'wpb_fine' ), $ids );
	}

	public function test_a_third_party_check_that_throws_in_id_is_dropped(): void {
		$bad = new class() implements CheckInterface {
			public function id(): string {
				throw new \RuntimeException( 'x' );
			}
			public function run( EnvironmentInterface $env ): CheckResult {
				return new CheckResult( 'x', 'php', Severity::Ok, 't', 'v' );
			}
		};
		$this->assertSame( array(), $this->ids( new EnvironmentReport( array() ), array( $bad ) ) );
	}

	public function test_the_real_built_ins_have_unique_valid_wpb_ids(): void {
		$ids = array_map( static fn( CheckInterface $c ): string => $c->id(), EnvironmentReport::builtins( new FrozenClock(), new SupportPolicy() ) );
		$this->assertSame( $ids, array_values( array_unique( $ids ) ) );
		foreach ( $ids as $id ) {
			$this->assertMatchesRegularExpression( '/^wpb_[a-z0-9_]{3,60}$/', $id );
		}
	}

	private function make( string $id, Severity $s, string $group = 'php', bool $dash = false ): CheckInterface {
		return new class( $id, $s, $group, $dash ) implements CheckInterface {
			public function __construct( private string $id, private Severity $s, private string $group, private bool $dash ) {
			}
			public function id(): string {
				return $this->id;
			}
			public function run( EnvironmentInterface $env ): CheckResult {
				return new CheckResult( $this->id, $this->group, $this->s, 't', 'v', '', '', false, $this->dash );
			}
		};
	}

	public function test_report_groups_and_counts(): void {
		$report = ( new EnvironmentReport(
			array(
				$this->make( 'wpb_a', Severity::Critical, 'versions' ),
				$this->make( 'wpb_b', Severity::Warning ),
				$this->make( 'wpb_c', Severity::Info ),
				$this->make( 'wpb_d', Severity::Ok ),
				$this->make( 'wpb_e', Severity::Unknown ),
				$this->make( 'wpb_f', Severity::Warning, 'wordpress', true ),
			)
		) )->run( new FakeEnvironment() );

		$this->assertSame( 6, $report->check_count() );
		$this->assertSame( 3, $report->issue_count(), 'critical + two warnings; info, ok and unknown are not issues' );
		$this->assertSame( array( 'critical', 'warning', 'info', 'unknown', 'ok' ), array_keys( $report->by_severity() ) );
		$this->assertSame( array( 'versions', 'php', 'wordpress' ), array_keys( $report->by_group() ) );
		$this->assertSame( Severity::Warning, $report->worst( array( 'php' ) ) );
		$this->assertSame( Severity::Ok, $report->worst( array( 'wordpress' ), true ), 'dashboard-only results stay out of Site Health' );
		$this->assertSame( Severity::Warning, $report->worst( array( 'wordpress' ), false ) );
		$this->assertSame( Severity::Critical, $report->worst( array( 'versions' ), true, array( 'wpb_a' ) ) );
		$this->assertSame( Severity::Ok, $report->worst( array( 'versions' ), true, array( 'wpb_zzz' ) ) );
	}
}
