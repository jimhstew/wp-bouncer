<?php
/**
 * An administrator's recent login locations.
 *
 * @package WPBouncer
 */

namespace WPBouncer\AdminLogins;

use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Immutable and pure PHP (no WordPress calls). Holds at most a handful of
 * entries: the network range (a /24 or /64), the country and the last time
 * each was used. Never a full IP address.
 */
final class LocationHistory {

	/** Entries accepted from stored data, however large the stored array is. */
	private const MAX_STORED = 100;

	/**
	 * Entries, oldest first.
	 *
	 * @var list<array{r: string, c: string, t: int}>
	 */
	private array $entries;
	/**
	 * Unix time the history was started.
	 *
	 * @var int
	 */
	private int $since;

	/**
	 * Set up the LocationHistory.
	 *
	 * @param int                                       $since   Unix time the history was started.
	 * @param list<array{r: string, c: string, t: int}> $entries Entries.
	 */
	private function __construct( int $since, array $entries ) {
		$this->since   = $since;
		$this->entries = $entries;
	}

	/**
	 * A new, empty history.
	 *
	 * @param int $now Unix time.
	 */
	public static function start( int $now ): self {
		return new self( $now, array() );
	}

	/**
	 * Read a stored value. Anything unexpected means "never recorded".
	 *
	 * @param mixed $raw Value from user meta.
	 * @return self|null Null for absent or invalid data.
	 */
	public static function from_meta( mixed $raw ): ?self {
		if ( ! is_array( $raw ) || ! isset( $raw['since'], $raw['e'] ) || ! is_int( $raw['since'] ) || $raw['since'] <= 0 || ! is_array( $raw['e'] ) ) {
			return null;
		}
		$entries = array();
		foreach ( array_slice( $raw['e'], 0, self::MAX_STORED ) as $entry ) {
			if ( ! is_array( $entry ) || ! isset( $entry['r'], $entry['c'], $entry['t'] ) || ! is_string( $entry['r'] ) || ! is_string( $entry['c'] ) || ! is_int( $entry['t'] ) || $entry['t'] <= 0 ) {
				continue;
			}
			if ( ! self::valid_range( $entry['r'] ) || ! preg_match( '/^(?:[A-Z]{2})?$/', $entry['c'] ) ) {
				continue;
			}
			$entries[] = array(
				'r' => $entry['r'],
				'c' => $entry['c'],
				't' => $entry['t'],
			);
		}
		return new self( $raw['since'], self::sorted( $entries ) );
	}

	/**
	 * Value to store (a plain array, never an object).
	 *
	 * @return array{since: int, e: list<array{r: string, c: string, t: int}>}
	 */
	public function to_meta(): array {
		return array(
			'since' => $this->since,
			'e'     => $this->entries,
		);
	}

	/**
	 * Entries, oldest first.
	 *
	 * @return list<array{r: string, c: string, t: int}>
	 */
	public function entries(): array {
		return $this->entries;
	}

	/** Unix time the history was started. */
	public function since(): int {
		return $this->since;
	}

	/**
	 * Is this range in the history?
	 *
	 * @param string $range Range as given by LoginLocationPolicy::range_of().
	 */
	public function has_range( string $range ): bool {
		foreach ( $this->entries as $entry ) {
			if ( $entry['r'] === $range ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Countries seen, without duplicates.
	 *
	 * @return string[]
	 */
	public function known_countries(): array {
		$out = array();
		foreach ( $this->entries as $entry ) {
			if ( '' !== $entry['c'] ) {
				$out[ $entry['c'] ] = $entry['c'];
			}
		}
		return array_values( $out );
	}

	/**
	 * History after a login.
	 *
	 * @param string $range   Range of the login.
	 * @param string $country Country code or ''.
	 * @param int    $now     Unix time.
	 * @param int    $window  Seconds an entry is kept.
	 * @param int    $max     Most entries kept.
	 */
	public function with_login( string $range, string $country, int $now, int $window, int $max ): self {
		$next = $this->pruned( $now, $window );
		if ( '' === $range || ! self::valid_range( $range ) ) {
			return $next;
		}
		$entries = array();
		$found   = false;
		foreach ( $next->entries as $entry ) {
			if ( $entry['r'] === $range ) {
				$entry['t'] = $now;
				if ( '' !== $country ) {
					$entry['c'] = $country;
				}
				$found = true;
			}
			$entries[] = $entry;
		}
		if ( ! $found ) {
			$entries[] = array(
				'r' => $range,
				'c' => $country,
				't' => $now,
			);
		}
		$entries = self::sorted( $entries );
		if ( count( $entries ) > max( 1, $max ) ) {
			$entries = array_slice( $entries, -max( 1, $max ) );
		}
		return new self( $next->since, $entries );
	}

	/**
	 * History without entries older than the window. `since` is kept.
	 *
	 * @param int $now    Unix time.
	 * @param int $window Seconds an entry is kept.
	 */
	public function pruned( int $now, int $window ): self {
		$cut = $now - $window;
		$out = array();
		foreach ( $this->entries as $entry ) {
			if ( $entry['t'] >= $cut ) {
				$out[] = $entry;
			}
		}
		return new self( $this->since, $out );
	}

	/**
	 * A range as written by LoginLocationPolicy: x.x.x.0/24 or a /64.
	 *
	 * @param string $range Candidate.
	 */
	private static function valid_range( string $range ): bool {
		if ( ! preg_match( '#^([0-9a-f:.]+)/(24|64)$#', $range, $m ) ) {
			return false;
		}
		return IpUtils::is_valid( $m[1] ) && ( '24' === $m[2] ) !== IpUtils::is_ipv6( $m[1] );
	}

	/**
	 * Oldest first, stable.
	 *
	 * @param list<array{r: string, c: string, t: int}> $entries Entries.
	 * @return list<array{r: string, c: string, t: int}>
	 */
	private static function sorted( array $entries ): array {
		usort(
			$entries,
			static fn( array $a, array $b ): int => $a['t'] <=> $b['t']
		);
		return $entries;
	}
}
