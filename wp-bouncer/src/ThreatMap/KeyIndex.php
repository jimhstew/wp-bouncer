<?php
/**
 * The capped index of threat map transients.
 *
 * @package WPBouncer
 */

namespace WPBouncer\ThreatMap;

defined( 'ABSPATH' ) || exit;

/**
 * Pure bookkeeping for the wpb_map_keys option: which transients exist (at most 20) and the
 * generation counter that makes old keys unreachable after a flush.
 */
final class KeyIndex {

	/** Most boxes kept. */
	public const CAP = 20;

	/**
	 * Check a value read from the option.
	 *
	 * @param mixed $raw Option value.
	 * @return array{gen: int, keys: array<string, int>}
	 */
	public static function normalise( $raw ): array {
		$gen  = 0;
		$keys = array();
		if ( is_array( $raw ) ) {
			$gen = is_int( $raw['gen'] ?? null ) ? max( 0, $raw['gen'] ) : 0;
			if ( is_array( $raw['keys'] ?? null ) ) {
				foreach ( $raw['keys'] as $name => $built ) {
					if ( is_string( $name ) && self::valid_name( $name ) && is_int( $built ) ) {
						$keys[ $name ] = $built;
					}
				}
			}
		}
		return array(
			'gen'  => $gen,
			'keys' => $keys,
		);
	}

	/**
	 * Is this a transient name we create?
	 *
	 * @param string $name Name.
	 */
	public static function valid_name( string $name ): bool {
		return 1 === preg_match( '/^wpb_map_[0-9a-f]{20}\z/', $name );
	}

	/**
	 * Record a box, evicting the oldest beyond the cap.
	 *
	 * @param array{gen: int, keys: array<string, int>} $index Current index.
	 * @param string                                    $name  Transient name.
	 * @param int                                       $now   Build time.
	 * @param int                                       $cap   Most entries.
	 * @return array{index: array{gen: int, keys: array<string, int>}, evicted: array<int, string>}
	 */
	public static function remember( array $index, string $name, int $now, int $cap = self::CAP ): array {
		$evicted = array();
		if ( ! self::valid_name( $name ) ) {
			return array(
				'index'   => $index,
				'evicted' => $evicted,
			);
		}
		unset( $index['keys'][ $name ] );
		$index['keys'][ $name ] = $now;
		// Oldest first. A stable sort keeps insertion order for equal times.
		$order = array_keys( $index['keys'] );
		usort(
			$order,
			static fn( string $a, string $b ): int => $index['keys'][ $a ] <=> $index['keys'][ $b ]
		);
		$surplus = count( $order ) - max( 1, $cap );
		for ( $i = 0; $i < $surplus; $i++ ) {
			$evicted[] = $order[ $i ];
			unset( $index['keys'][ $order[ $i ] ] );
		}
		return array(
			'index'   => $index,
			'evicted' => $evicted,
		);
	}

	/**
	 * The index after a flush: empty, with the next generation.
	 *
	 * @param array{gen: int, keys: array<string, int>} $index Current index.
	 * @return array{gen: int, keys: array<string, int>}
	 */
	public static function flushed( array $index ): array {
		return array(
			'gen'  => $index['gen'] + 1,
			'keys' => array(),
		);
	}
}
