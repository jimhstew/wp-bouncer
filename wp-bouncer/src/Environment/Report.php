<?php
/**
 * The results of one run.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

defined( 'ABSPATH' ) || exit;

/**
 * Read-only collection with the groupings the screens need.
 */
final class Report {

	/**
	 * Results in the order the checks ran.
	 *
	 * @var CheckResult[]
	 */
	private array $results;

	/**
	 * Set up the Report.
	 *
	 * @param CheckResult[] $results Results.
	 */
	public function __construct( array $results ) {
		$this->results = array_values( $results );
	}

	/**
	 * All results.
	 *
	 * @return CheckResult[]
	 */
	public function results(): array {
		return $this->results;
	}

	/**
	 * Results by severity value, worst first; empty severities are omitted.
	 *
	 * @return array<string, CheckResult[]>
	 */
	public function by_severity(): array {
		$cases = Severity::cases();
		usort( $cases, static fn( Severity $a, Severity $b ): int => $b->rank() <=> $a->rank() );
		$out = array();
		foreach ( $cases as $severity ) {
			$rows = array_values( array_filter( $this->results, static fn( CheckResult $r ): bool => $r->severity === $severity ) );
			if ( $rows ) {
				$out[ $severity->value ] = $rows;
			}
		}
		return $out;
	}

	/**
	 * Results by group (versions, php, WordPress).
	 *
	 * @return array<string, CheckResult[]>
	 */
	public function by_group(): array {
		$out = array();
		foreach ( $this->results as $result ) {
			$out[ $result->group ][] = $result;
		}
		return $out;
	}

	/** Number of findings that need attention (critical, warning, notice). */
	public function issue_count(): int {
		return count( array_filter( $this->results, static fn( CheckResult $r ): bool => $r->severity->is_issue() ) );
	}

	/** Number of checks that ran. */
	public function check_count(): int {
		return count( $this->results );
	}

	/**
	 * The worst severity among some results.
	 *
	 * @param string[] $groups         Groups to include.
	 * @param bool     $site_health    Leave out Dashboard-only results.
	 * @param string[] $only_ids       If not empty, only these ids.
	 */
	public function worst( array $groups, bool $site_health = true, array $only_ids = array() ): Severity {
		$worst = Severity::Ok;
		foreach ( $this->results as $r ) {
			if ( ! in_array( $r->group, $groups, true ) || ( $site_health && $r->dashboard_only ) || ( $only_ids && ! in_array( $r->id, $only_ids, true ) ) ) {
				continue;
			}
			if ( $r->severity->rank() > $worst->rank() ) {
				$worst = $r->severity;
			}
		}
		return $worst;
	}
}
