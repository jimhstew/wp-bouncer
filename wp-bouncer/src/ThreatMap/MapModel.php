<?php
/**
 * Dots, unplaced rows and panel state for the threat map.
 *
 * @package WPBouncer
 */

namespace WPBouncer\ThreatMap;

defined( 'ABSPATH' ) || exit;

/**
 * Turns a CountryTally into drawable dots using the generated Centroids. Pure PHP.
 */
final class MapModel {

	/**
	 * Build the model.
	 *
	 * @param CountryTally                                              $tally    Tally.
	 * @param (callable(string): (array{0: float, 1: float}|null))|null $point Code => [x, y] or null for codes with no place on the map, such as T1, EU, AP and AQ (default: Centroids::point()).
	 * @return array{dots: array<int, array{code: string, count: int, x: float, y: float, r: float, bucket: int}>, unplaced: array<string, int>, min: int, max: int, unknown: int, total: int, plotted_total: int}
	 */
	public static function build( CountryTally $tally, ?callable $point = null ): array {
		$point ??= array( Centroids::class, 'point' );
		$dots    = array();
		$off     = array();
		foreach ( $tally->countries() as $code => $count ) {
			$xy = $point( (string) $code );
			if ( is_array( $xy ) && isset( $xy[0], $xy[1] ) ) {
				$dots[] = array(
					'code'   => (string) $code,
					'count'  => $count,
					'x'      => (float) $xy[0],
					'y'      => (float) $xy[1],
					'r'      => 0.0,
					'bucket' => 0,
				);
			} else {
				$off[ (string) $code ] = $count;
			}
		}

		$counts = array_column( $dots, 'count' );
		$min    = $counts ? min( $counts ) : 0;
		$max    = $counts ? max( $counts ) : 0;
		foreach ( $dots as $i => $dot ) {
			$bucket               = HeatScale::bucket( $dot['count'], $min, $max );
			$dots[ $i ]['bucket'] = $bucket;
			$dots[ $i ]['r']      = HeatScale::radius( $bucket );
		}
		return array(
			'dots'          => $dots,
			'unplaced'      => $off,
			'min'           => $min,
			'max'           => $max,
			'unknown'       => $tally->unknown(),
			'total'         => $tally->total(),
			'plotted_total' => array_sum( $counts ),
		);
	}

	/**
	 * Which of the panel states applies.
	 *
	 * @param bool              $runnable   ThreatQuery::runnable().
	 * @param string            $load       ok | busy | error.
	 * @param CountryTally|null $tally      Tally when load is ok.
	 * @param bool              $geo_loaded Whether a geolocation database is loaded.
	 * @return string filtered_out | busy | error | no_geo | empty | ok.
	 */
	public static function state( bool $runnable, string $load, ?CountryTally $tally, bool $geo_loaded ): string {
		if ( ! $runnable ) {
			return 'filtered_out';
		}
		if ( 'busy' === $load || 'error' === $load ) {
			return $load;
		}
		if ( null === $tally || 0 === $tally->total() ) {
			return 'empty';
		}
		if ( ! $geo_loaded && array() === $tally->countries() ) {
			return 'no_geo';
		}
		return 'ok';
	}
}
