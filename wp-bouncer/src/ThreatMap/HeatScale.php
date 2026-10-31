<?php
/**
 * Logarithmic colour/size buckets for the threat map.
 *
 * @package WPBouncer
 */

namespace WPBouncer\ThreatMap;

defined( 'ABSPATH' ) || exit;

/**
 * Maps a count to a bucket 0-7 and a dot radius. Pure PHP.
 */
final class HeatScale {

	/** Number of buckets. */
	public const STEPS = 8;

	/**
	 * Bucket for a count between the smallest and largest on the map.
	 *
	 * @param int $count Count (at least 1).
	 * @param int $min   Smallest count on the map.
	 * @param int $max   Largest count on the map.
	 * @return int 0 to 7. With no spread (max <= min) every dot is the top bucket.
	 */
	public static function bucket( int $count, int $min, int $max ): int {
		if ( $max <= $min || $min < 1 ) {
			return self::STEPS - 1;
		}
		$count = max( $min, min( $max, $count ) );
		$t     = ( log( $count ) - log( $min ) ) / ( log( $max ) - log( $min ) );
		return max( 0, min( self::STEPS - 1, (int) floor( $t * self::STEPS ) ) );
	}

	/**
	 * Dot radius in map units (size is a second cue besides colour).
	 *
	 * @param int $bucket Bucket 0-7.
	 */
	public static function radius( int $bucket ): float {
		return 5.0 + 0.75 * max( 0, min( self::STEPS - 1, $bucket ) );
	}
}
