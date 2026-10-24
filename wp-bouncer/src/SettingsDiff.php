<?php
/**
 * Compares two settings arrays for the configuration audit.
 *
 * @package WPBouncer
 */

namespace WPBouncer;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP: no WordPress calls.
 *
 * A change is a dotted key path such as "rules.login_lockout.enabled". Values
 * that are lists (the allowlist, trusted proxies, blocked IPs, countries) count
 * as one path, so the audit never has to carry the addresses themselves.
 */
final class SettingsDiff {

	/** Top-level keys whose change is always worth an alert. */
	private const RISKY_KEYS = array( 'allowlist', 'trusted_proxies', 'ip_source', 'geo_source', 'geo_header', 'alerts.enabled', 'alerts.firewall_changes', 'alerts.recipients', 'rules.xmlrpc.mode' );

	/** Longest Activity Log reason (the column is varchar(255)). */
	private const REASON_MAX = 255;

	/**
	 * Key paths that differ between two settings arrays.
	 *
	 * @param array<string, mixed> $before Settings before.
	 * @param array<string, mixed> $after  Settings after.
	 * @return string[] Changed paths, in a stable (sorted) order.
	 */
	public static function changes( array $before, array $after ): array {
		$out = array();
		self::walk( $before, $after, '', $out );
		sort( $out, SORT_STRING );
		return $out;
	}

	/**
	 * The changes that weaken or redirect the firewall, or that silence its alerts.
	 *
	 * Risky:
	 * - the allowlist, trusted proxies, IP source, geo source and geo header;
	 * - the mode, when it moves away from "enforce";
	 * - the alert switches and recipients;
	 * - any rule switch (a boolean under rules.*) going from true to false;
	 * - everything under rules.country, and rules.xmlrpc.mode;
	 * - rules.waf.excluded_params gaining entries;
	 * - rules.ip_blocklist.ips and rules.user_agent.patterns getting shorter;
	 * - log_retention_days or traffic.retention_days getting smaller.
	 *
	 * Numeric thresholds (attempt counts, windows, limits) and texts stay
	 * log-only: they are audited in the Activity Log but never emailed.
	 *
	 * @param string[]             $changes Output of changes().
	 * @param array<string, mixed> $before  Settings before.
	 * @param array<string, mixed> $after   Settings after.
	 * @return string[] The risky subset of $changes.
	 */
	public static function risky( array $changes, array $before, array $after ): array {
		$out = array();
		foreach ( $changes as $path ) {
			if ( self::is_risky( $path, self::value_at( $before, $path ), self::value_at( $after, $path ) ) ) {
				$out[] = $path;
			}
		}
		return $out;
	}

	/**
	 * One-line, length-capped description for the Activity Log.
	 *
	 * The actor and the risky paths come first and always survive; only the
	 * list of other changes is cut.
	 *
	 * @param string   $actor   Login of the acting user.
	 * @param string[] $changes All changed paths.
	 * @param string[] $risky   The risky subset.
	 * @return string Reason text, at most 255 characters.
	 */
	public static function describe( string $actor, array $changes, array $risky ): string {
		$other  = array_values( array_diff( $changes, $risky ) );
		$head   = 'Settings changed by ' . $actor . ': ';
		$reason = $head . implode( ', ', empty( $risky ) ? $other : $risky );
		if ( ! empty( $risky ) && ! empty( $other ) ) {
			$reason .= '; also: ' . implode( ', ', $other );
		}
		if ( mb_strlen( $reason ) > self::REASON_MAX ) {
			$reason = mb_substr( $reason, 0, self::REASON_MAX - 3 ) . '...';
		}
		return $reason;
	}

	/**
	 * Is this one change risky?
	 *
	 * @param string $path   Changed path.
	 * @param mixed  $before Value before.
	 * @param mixed  $after  Value after.
	 */
	private static function is_risky( string $path, $before, $after ): bool {
		if ( in_array( $path, self::RISKY_KEYS, true ) ) {
			return true;
		}
		// A shorter retention makes the daily purge erase older audit rows.
		if ( 'log_retention_days' === $path || 'traffic.retention_days' === $path ) {
			return (int) $after < (int) $before;
		}
		if ( 'mode' === $path ) {
			return 'enforce' === $before && 'enforce' !== $after;
		}
		if ( 0 !== strpos( $path, 'rules.' ) ) {
			return false;
		}
		if ( 0 === strpos( $path, 'rules.country.' ) ) {
			return true;
		}
		if ( true === $before && true !== $after ) {
			return true;
		}
		if ( 'rules.waf.excluded_params' === $path ) {
			return array() !== array_diff( (array) $after, (array) $before );
		}
		if ( 'rules.ip_blocklist.ips' === $path || 'rules.user_agent.patterns' === $path ) {
			return count( (array) $after ) < count( (array) $before );
		}
		return false;
	}

	/**
	 * Recursive comparison.
	 *
	 * @param mixed    $before    Old value.
	 * @param mixed    $after    New value.
	 * @param string   $path   Path so far.
	 * @param string[] $out    Collected paths.
	 */
	private static function walk( $before, $after, string $path, array &$out ): void {
		if ( is_array( $before ) && is_array( $after ) && ! self::is_filled_list( $before ) && ! self::is_filled_list( $after ) ) {
			foreach ( array_unique( array_merge( array_keys( $before ), array_keys( $after ) ) ) as $key ) {
				$child = '' === $path ? (string) $key : $path . '.' . $key;
				self::walk( $before[ $key ] ?? null, $after[ $key ] ?? null, $child, $out );
			}
			return;
		}
		if ( $before !== $after && '' !== $path ) {
			$out[] = $path;
		}
	}

	/**
	 * Is this a non-empty list (sequential integer keys)?
	 *
	 * @param array<mixed> $value Array.
	 */
	private static function is_filled_list( array $value ): bool {
		return array() !== $value && array_is_list( $value );
	}

	/**
	 * Read a dotted path.
	 *
	 * @param array<string, mixed> $settings Settings.
	 * @param string               $path     Dotted path.
	 * @return mixed Value, or null when absent.
	 */
	private static function value_at( array $settings, string $path ) {
		$value = $settings;
		foreach ( explode( '.', $path ) as $key ) {
			if ( ! is_array( $value ) || ! array_key_exists( $key, $value ) ) {
				return null;
			}
			$value = $value[ $key ];
		}
		return $value;
	}
}
