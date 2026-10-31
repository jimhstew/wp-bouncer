<?php
/**
 * Threat counts per valid country, plus an "unknown" bucket.
 *
 * @package WPBouncer
 */

namespace WPBouncer\ThreatMap;

use WPBouncer\Geo\Countries;

defined( 'ABSPATH' ) || exit;

/**
 * Merges raw stored country values (case differences, blanks, junk) into validated codes. Pure PHP.
 *
 * Anything that is not a known code counts as unknown. It is never dropped and never emitted.
 */
final class CountryTally {

	/**
	 * Code => count, largest first.
	 *
	 * @var array<string, int>
	 */
	private array $countries;

	/**
	 * Threats with no usable country.
	 *
	 * @var int
	 */
	private int $unknown;

	/**
	 * Use from_rows() or from_array().
	 *
	 * @param array<string, int> $countries Code => count.
	 * @param int                $unknown   Unknown count.
	 */
	private function __construct( array $countries, int $unknown ) {
		uksort(
			$countries,
			static function ( $a, $b ) use ( $countries ): int {
				$by_count = $countries[ $b ] <=> $countries[ $a ];
				return 0 !== $by_count ? $by_count : strcmp( (string) $a, (string) $b );
			}
		);
		$this->countries = $countries;
		$this->unknown   = $unknown;
	}

	/**
	 * Build from raw rows.
	 *
	 * @param array<int|string, int|string> $raw Stored value => count.
	 */
	public static function from_rows( array $raw ): self {
		$countries = array();
		$unknown   = 0;
		foreach ( $raw as $value => $n ) {
			$n = max( 0, (int) $n );
			if ( 0 === $n ) {
				continue;
			}
			$code = strtoupper( trim( (string) $value ) );
			if ( 1 === preg_match( '/^[A-Z][A-Z0-9]\z/', $code ) && Countries::is_valid( $code ) ) {
				$countries[ $code ] = ( $countries[ $code ] ?? 0 ) + $n;
			} else {
				$unknown += $n;
			}
		}
		return new self( $countries, $unknown );
	}

	/**
	 * Rebuild from the cached array, validating it again (a tampered transient can't inject values).
	 *
	 * @param mixed $data Output of to_array().
	 */
	public static function from_array( $data ): self {
		if ( ! is_array( $data ) ) {
			return new self( array(), 0 );
		}
		$rows = is_array( $data['countries'] ?? null ) ? $data['countries'] : array();
		$safe = array();
		foreach ( $rows as $code => $n ) {
			if ( is_int( $n ) || ( is_string( $n ) && ctype_digit( $n ) ) ) {
				$safe[ (string) $code ] = (int) $n;
			}
		}
		$tally = self::from_rows( $safe );
		$extra = isset( $data['unknown'] ) && is_int( $data['unknown'] ) ? max( 0, $data['unknown'] ) : 0;
		return new self( $tally->countries, $tally->unknown + $extra );
	}

	/**
	 * Code => count, largest first, ties by code.
	 *
	 * @return array<string, int>
	 */
	public function countries(): array {
		return $this->countries;
	}

	/**
	 * Threats with no usable country.
	 */
	public function unknown(): int {
		return $this->unknown;
	}

	/**
	 * All threats, known and unknown.
	 */
	public function total(): int {
		return array_sum( $this->countries ) + $this->unknown;
	}

	/**
	 * Plain array for the cache.
	 *
	 * @return array{countries: array<string, int>, unknown: int}
	 */
	public function to_array(): array {
		return array(
			'countries' => $this->countries,
			'unknown'   => $this->unknown,
		);
	}
}
