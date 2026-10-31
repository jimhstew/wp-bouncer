<?php
/**
 * When the threat map's cached numbers are served, rebuilt or refused.
 *
 * @package WPBouncer
 */

namespace WPBouncer\ThreatMap;

use WPBouncer\Admin\DashboardWidget;

defined( 'ABSPATH' ) || exit;

/**
 * Pure decision logic for ThreatMapPanel's transients.
 */
final class CachePolicy {

	public const FRESH = 'fresh';
	public const STALE = 'stale';
	public const BUILD = 'build';
	public const BUSY  = 'busy';

	/** Default time a box counts as fresh, in seconds. */
	public const DEFAULT_TTL = 300;

	/** Shortest and longest fresh time, in seconds. */
	public const MIN_TTL = 60;
	public const MAX_TTL = 3600;

	/** Threats in the window above which the numbers are cached for the longest time (the widget's FLOOD_ROWS). */
	public const FLOOD_ROWS = DashboardWidget::FLOOD_ROWS;

	/**
	 * Decide what to do.
	 *
	 * @param array{built: int, fresh_until: int, tally: array<mixed>}|null $box       The cached box (null: none).
	 * @param int                                                           $now       Current Unix time.
	 * @param bool                                                          $locked    Another request is building a map.
	 * @param bool                                                          $throttled This user built one a moment ago.
	 * @return string fresh | stale | build | busy
	 */
	public static function decide( ?array $box, int $now, bool $locked, bool $throttled ): string {
		if ( null === $box ) {
			return $throttled ? self::BUSY : self::BUILD;
		}
		if ( $now < $box['fresh_until'] ) {
			return self::FRESH;
		}
		return ( $locked || $throttled ) ? self::STALE : self::BUILD;
	}

	/**
	 * Seconds a new box counts as fresh.
	 *
	 * @param int $requested The (filtered) wanted TTL.
	 * @param int $total     Threats in the window.
	 */
	public static function ttl( int $requested, int $total ): int {
		if ( $total > self::FLOOD_ROWS ) {
			return self::MAX_TTL;
		}
		return max( self::MIN_TTL, min( self::MAX_TTL, $requested ) );
	}

	/**
	 * A box as stored in the transient.
	 *
	 * @param int                  $built Build time.
	 * @param int                  $ttl   Fresh seconds.
	 * @param array<string, mixed> $tally CountryTally::to_array().
	 * @return array{v: int, built: int, fresh_until: int, tally: array<string, mixed>}
	 */
	public static function make_box( int $built, int $ttl, array $tally ): array {
		return array(
			'v'           => 1,
			'built'       => $built,
			'fresh_until' => $built + $ttl,
			'tally'       => $tally,
		);
	}

	/**
	 * Check a value read from a transient.
	 *
	 * @param mixed $raw What get_transient() returned.
	 * @return array{built: int, fresh_until: int, tally: array<mixed>}|null Null when missing or malformed.
	 */
	public static function normalise_box( $raw ): ?array {
		if ( ! is_array( $raw ) || 1 !== ( $raw['v'] ?? null ) || ! is_int( $raw['built'] ?? null ) || ! is_int( $raw['fresh_until'] ?? null ) || ! is_array( $raw['tally'] ?? null ) ) {
			return null;
		}
		return array(
			'built'       => $raw['built'],
			'fresh_until' => $raw['fresh_until'],
			'tally'       => $raw['tally'],
		);
	}
}
