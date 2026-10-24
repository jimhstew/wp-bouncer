<?php
/**
 * Rule state and warnings for the admin screens (no WordPress calls).
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * One source of truth for "is this rule on, and is it working": the admin
 * notices, the Rules tab, the Dashboard tab and the Dashboard widget read it.
 *
 * Every rule gets its saved on/off state and, where the plugin can tell, a
 * flag with reason codes:
 *
 * - attention: on, but not (fully) working. Counted as "needs attention".
 * - setup: off, and needs set-up before it is useful. A neutral hint, not counted.
 */
final class RuleStatus {

	public const FLAG_ATTENTION = 'attention';
	public const FLAG_SETUP     = 'setup';

	// Reason codes. Stable: tests and views use them.
	public const NO_GEO_DB            = 'no_geo_db';
	public const GEO_HEADER_UNTRUSTED = 'geo_header_untrusted';
	public const UPLOADS_BROKEN       = 'uploads_broken';
	public const UPLOADS_WRITE_FAILED = 'uploads_write_failed';
	public const NO_COUNTRIES         = 'no_countries';
	public const ALLOW_LIST_EMPTY     = 'allow_list_empty';
	public const UPLOADS_UNPROTECTED  = 'uploads_unprotected';
	public const SETUP_COUNTRY        = 'setup_country';
	public const SETUP_RATE_LIMIT     = 'setup_rate_limit';

	/**
	 * Status of every built-in rule.
	 *
	 * @param array<string, mixed> $facts Keys: rules (the settings' rules array), geo_rows (int), geo_source (string),
	 *                                    geo_header_untrusted (bool, Plugin::country_paused()), disabled (bool, WP_BOUNCER_DISABLE),
	 *                                    uploads_state (array|null, the .htaccess state option), uploads_probe (string|null, last test result).
	 * @return array<string, array{on: bool, flag: string|null, reasons: string[]}> Keyed by every built-in id.
	 */
	public static function builtin( array $facts ): array {
		$out = array();
		foreach ( RuleCatalog::builtin_ids() as $id ) {
			$rule       = $facts['rules'][ $id ] ?? array();
			$on         = ! empty( $rule['enabled'] );
			$reasons    = array();
			$flag       = null;
			$no_geo_yet = 0 === (int) ( $facts['geo_rows'] ?? 0 ) && 'header' !== ( $facts['geo_source'] ?? 'database' );

			if ( 'country' === $id ) {
				if ( $on ) {
					if ( $no_geo_yet ) {
						$reasons[] = self::NO_GEO_DB;
					}
					if ( ! empty( $facts['geo_header_untrusted'] ) ) {
						$reasons[] = self::GEO_HEADER_UNTRUSTED;
					}
					if ( empty( $rule['countries'] ) ) {
						if ( 'allow' === ( $rule['mode'] ?? 'block' ) ) {
							$reasons[] = self::ALLOW_LIST_EMPTY;
						} elseif ( empty( $rule['block_unknown'] ) ) {
							// With "block unknown" on, an empty block list still refuses unidentified IPs.
							$reasons[] = self::NO_COUNTRIES;
						}
					}
				} elseif ( $no_geo_yet ) {
					$reasons[] = self::SETUP_COUNTRY;
					$flag      = self::FLAG_SETUP;
				}
			} elseif ( 'uploads_php' === $id ) {
				$state = $facts['uploads_state'] ?? null;
				$wants = empty( $facts['disabled'] ) && $on && ! empty( $rule['htaccess'] );
				if ( $wants && is_array( $state ) && ! empty( $state['broken'] ) ) {
					$reasons[] = self::UPLOADS_BROKEN;
				} elseif ( $wants && is_array( $state ) && empty( $state['ok'] ) ) {
					$reasons[] = self::UPLOADS_WRITE_FAILED;
				}
				if ( $on && 'unprotected' === ( $facts['uploads_probe'] ?? null ) ) {
					$reasons[] = self::UPLOADS_UNPROTECTED;
				}
			} elseif ( 'rate_limit' === $id && ! $on ) {
				$reasons[] = self::SETUP_RATE_LIMIT;
				$flag      = self::FLAG_SETUP;
			}

			if ( null === $flag && array() !== $reasons ) {
				$flag = self::FLAG_ATTENTION;
			}
			$out[ $id ] = array(
				'on'      => $on,
				'flag'    => $flag,
				'reasons' => $reasons,
			);
		}
		return $out;
	}

	/**
	 * Counts per category.
	 *
	 * @param array<string, string[]>                           $groups   From RuleCatalog::group().
	 * @param array<string, array{on: bool, flag: string|null}> $statuses Built-in plus third-party (third-party: flag null).
	 * @return array<string, array{on: int, total: int, attention: int}>
	 */
	public static function summarise( array $groups, array $statuses ): array {
		$out = array();
		foreach ( $groups as $slug => $ids ) {
			$row = array(
				'on'        => 0,
				'total'     => 0,
				'attention' => 0,
			);
			foreach ( $ids as $id ) {
				if ( ! isset( $statuses[ $id ] ) ) {
					continue;
				}
				++$row['total'];
				if ( ! empty( $statuses[ $id ]['on'] ) ) {
					++$row['on'];
				}
				if ( self::FLAG_ATTENTION === ( $statuses[ $id ]['flag'] ?? null ) ) {
					++$row['attention'];
				}
			}
			$out[ $slug ] = $row;
		}
		return $out;
	}

	/**
	 * Whole-plugin totals (for the Dashboard widget's status line).
	 *
	 * @param array<string, string[]>                           $groups   From RuleCatalog::group().
	 * @param array<string, array{on: bool, flag: string|null}> $statuses As for summarise().
	 * @return array{on: int, total: int, attention: int}
	 */
	public static function totals( array $groups, array $statuses ): array {
		$sum = array(
			'on'        => 0,
			'total'     => 0,
			'attention' => 0,
		);
		foreach ( self::summarise( $groups, $statuses ) as $row ) {
			$sum['on']        += $row['on'];
			$sum['total']     += $row['total'];
			$sum['attention'] += $row['attention'];
		}
		return $sum;
	}
}
