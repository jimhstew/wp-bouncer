<?php
/**
 * The validated filter set behind the threat map.
 *
 * @package WPBouncer
 */

namespace WPBouncer\ThreatMap;

use WPBouncer\Geo\Countries;
use WPBouncer\Log\BlockLog;
use WPBouncer\Log\DateRange;

defined( 'ABSPATH' ) || exit;

/**
 * Keeps only rule, action and country (free-text search and the single-IP filter never apply to the map),
 * validates them and names the cache entry. Pure PHP.
 */
final class ThreatQuery {

	/**
	 * Rule id filter ('' = any).
	 *
	 * @var string
	 */
	private string $rule = '';

	/**
	 * Action filter ('' = any threat action).
	 *
	 * @var string
	 */
	private string $action = '';

	/**
	 * Country filter ('' = any).
	 *
	 * @var string
	 */
	private string $country = '';

	/**
	 * Window start (UTC).
	 *
	 * @var string
	 */
	private string $since;

	/**
	 * Window end (UTC, exclusive).
	 *
	 * @var string
	 */
	private string $until;

	/**
	 * Why the query can't run ('' when it can): action | country | rule.
	 *
	 * @var string
	 */
	private string $reason = '';

	/**
	 * Use from_filters().
	 *
	 * @param string $since Window start.
	 * @param string $until Window end.
	 */
	private function __construct( string $since, string $until ) {
		$this->since = $since;
		$this->until = $until;
	}

	/**
	 * Build from the Activity Log filters and the date range.
	 *
	 * @param array<string, string> $log_filters Filters as AdminController::log_filters_from_request() returns them.
	 * @param DateRange             $range       Date range.
	 */
	public static function from_filters( array $log_filters, DateRange $range ): self {
		$q = new self( $range->since_utc, $range->until_utc );

		$action = isset( $log_filters['action'] ) && is_scalar( $log_filters['action'] ) ? (string) $log_filters['action'] : '';
		if ( '' !== $action ) {
			if ( in_array( $action, BlockLog::THREAT_ACTIONS, true ) ) {
				$q->action = $action;
			} else {
				$q->reason = 'action';
			}
		}

		$country = isset( $log_filters['country'] ) && is_scalar( $log_filters['country'] ) ? strtoupper( (string) $log_filters['country'] ) : '';
		if ( '' !== $country ) {
			if ( 1 === preg_match( '/^[A-Z][A-Z0-9]\z/', $country ) && Countries::is_valid( $country ) ) {
				$q->country = $country;
			} elseif ( '' === $q->reason ) {
				$q->reason = 'country';
			}
		}

		$rule = isset( $log_filters['rule'] ) && is_scalar( $log_filters['rule'] ) ? (string) $log_filters['rule'] : '';
		if ( '' !== $rule ) {
			if ( 1 === preg_match( '/^[a-z0-9_-]{1,32}\z/', $rule ) ) {
				$q->rule = $rule;
			} elseif ( '' === $q->reason ) {
				$q->reason = 'rule';
			}
		}
		return $q;
	}

	/**
	 * Can the query run? False when a filter can never match a threat.
	 */
	public function runnable(): bool {
		return '' === $this->reason;
	}

	/**
	 * Which filter made the query unrunnable ('' when it can run).
	 */
	public function reason(): string {
		return $this->reason;
	}

	/**
	 * The filters to pass to ThreatMapSource (only non-empty ones).
	 *
	 * @return array<string, string>
	 */
	public function filters(): array {
		return array_filter(
			array(
				'rule'    => $this->rule,
				'action'  => $this->action,
				'country' => $this->country,
			),
			static fn( string $v ): bool => '' !== $v
		);
	}

	/**
	 * Window start (UTC, inclusive).
	 */
	public function since(): string {
		return $this->since;
	}

	/**
	 * Window end (UTC, exclusive).
	 */
	public function until(): string {
		return $this->until;
	}

	/**
	 * Active country filter ('' when none).
	 */
	public function country(): string {
		return $this->country;
	}

	/**
	 * Transient name for this query: wpb_map_ plus 20 hex characters. Request text never appears in it.
	 *
	 * @param int $generation The generation counter from KeyIndex.
	 */
	public function cache_key( int $generation ): string {
		$payload = array(
			'v'       => 1,
			'g'       => $generation,
			'rule'    => $this->rule,
			'action'  => $this->action,
			'country' => $this->country,
			'since'   => $this->since,
			'until'   => $this->until,
		);
		return 'wpb_map_' . substr( hash( 'sha256', (string) json_encode( $payload ) ), 0, 20 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- pure class, no WordPress calls; the payload is plain strings and ints.
	}
}
