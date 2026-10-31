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
	private const RISKY_KEYS = array( 'settings', 'allowlist', 'trusted_proxies', 'ip_source', 'geo_source', 'geo_header', 'alerts.enabled', 'alerts.firewall_changes', 'alerts.recipients', 'rules.xmlrpc.mode' );

	/**
	 * Settings that hold a list. They count as one path whatever shape they were
	 * written in, so a non-list array can't hide behind child paths.
	 */
	private const LIST_PATHS = array(
		'allowlist',
		'trusted_proxies',
		'alerts.recipients',
		'rules.ip_blocklist.ips',
		'rules.user_agent.patterns',
		'rules.country.countries',
		'rules.login_lockout.banned_usernames',
		'rules.waf.excluded_params',
		'rules.sensitive_files.extra_paths',
	);

	/** Longest single path, and most paths, passed on by safe_paths(). */
	private const PATH_MAX  = 64;
	private const PATHS_MAX = 20;

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
		self::walk( $before, $after, '', $out, Settings::defaults() );
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
	 * Make paths safe to log, email and pass to listeners.
	 *
	 * Keeps only [A-Za-z0-9_.-] (an emptied path becomes "?"), cuts each path at
	 * 64 characters and keeps at most 20, adding "+N more".
	 *
	 * @param string[] $paths Changed paths.
	 * @return string[] Safe paths.
	 */
	public static function safe_paths( array $paths ): array {
		$out = array();
		foreach ( $paths as $path ) {
			$clean = (string) preg_replace( '/[^A-Za-z0-9_.-]/', '', (string) $path );
			$out[] = '' === $clean ? '?' : substr( $clean, 0, self::PATH_MAX );
		}
		if ( count( $out ) > self::PATHS_MAX ) {
			$extra = count( $out ) - self::PATHS_MAX;
			$out   = array_slice( $out, 0, self::PATHS_MAX );
			$out[] = '+' . $extra . ' more';
		}
		return $out;
	}

	/**
	 * Is this one change risky?
	 *
	 * @param string $path   Changed path.
	 * @param mixed  $before Value before.
	 * @param mixed  $after  Value after.
	 */
	private static function is_risky( string $path, $before, $after ): bool {
		foreach ( self::RISKY_KEYS as $key ) {
			if ( $path === $key || 0 === strpos( $path, $key . '.' ) ) {
				return true;
			}
		}
		// A shorter retention makes the daily purge erase older audit rows.
		if ( 'log_retention_days' === $path || 'traffic.retention_days' === $path ) {
			return (int) $after < (int) $before;
		}
		if ( 'mode' === $path ) {
			return 'enforce' === $before && 'enforce' !== $after;
		}
		// Any alert switch going from on to off (new switches are covered automatically).
		if ( 0 === strpos( $path, 'alerts.' ) ) {
			return true === $before && true !== $after;
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
			$added = (array) $after;
			if ( count( $added ) !== count( array_filter( $added, 'is_scalar' ) ) ) {
				return true; // A nested array in a list of names is never an ordinary exclusion.
			}
			return array() !== array_diff( $added, array_filter( (array) $before, 'is_scalar' ) );
		}
		if ( 'rules.ip_blocklist.ips' === $path || 'rules.user_agent.patterns' === $path ) {
			return count( (array) $after ) < count( (array) $before );
		}
		return false;
	}

	/**
	 * Recursive comparison.
	 *
	 * Goes deeper only where the schema (the defaults) has an array with named
	 * keys at that path; everything else is a leaf, and keys the schema doesn't
	 * know never become paths.
	 *
	 * @param mixed    $before Old value.
	 * @param mixed    $after  New value.
	 * @param string   $path   Path so far.
	 * @param string[] $out    Collected paths.
	 * @param mixed    $schema Defaults at this path.
	 */
	private static function walk( $before, $after, string $path, array &$out, $schema ): void {
		if ( is_array( $schema ) && array() !== $schema && ! array_is_list( $schema ) && ! in_array( $path, self::LIST_PATHS, true ) && is_array( $before ) && is_array( $after ) ) {
			foreach ( array_keys( $schema ) as $key ) {
				$child = '' === $path ? (string) $key : $path . '.' . $key;
				self::walk( $before[ $key ] ?? null, $after[ $key ] ?? null, $child, $out, $schema[ $key ] );
			}
			return;
		}
		if ( $before !== $after && '' !== $path ) {
			$out[] = $path;
		}
	}

	/**
	 * The settings leaves of a raw option value, for the drift fingerprint.
	 *
	 * Walks the schema (the defaults) with the same rules as changes(): it descends only into
	 * arrays with named keys, treats each list path as one leaf and never makes a path from a key
	 * the schema doesn't know. Values come from the raw option, not the normalised settings.
	 *
	 * @param mixed $raw Raw option value (anything the options API can hold).
	 * @return array<string, array{0: bool, 1: mixed}> Path => [present, value]. "present" is false
	 *                                                  when the path is missing or a parent is not an array.
	 */
	public static function leaves( mixed $raw ): array {
		$out = array();
		self::collect( $raw, is_array( $raw ), '', Settings::defaults(), $out );
		return $out;
	}

	/**
	 * Collect the leaves below one schema node.
	 *
	 * @param mixed                $value   Raw value at this path.
	 * @param bool                 $present True when the path is there.
	 * @param string               $path    Path so far.
	 * @param mixed                $schema  Defaults at this path.
	 * @param array<string, mixed> $out     Collected leaves.
	 */
	private static function collect( mixed $value, bool $present, string $path, mixed $schema, array &$out ): void {
		if ( is_array( $schema ) && array() !== $schema && ! array_is_list( $schema ) && ! in_array( $path, self::LIST_PATHS, true ) ) {
			foreach ( array_keys( $schema ) as $key ) {
				$has   = $present && is_array( $value ) && array_key_exists( $key, $value );
				$child = '' === $path ? (string) $key : $path . '.' . $key;
				self::collect( $has ? $value[ $key ] : null, $has, $child, $schema[ $key ], $out );
			}
			return;
		}
		if ( '' !== $path ) {
			$out[ $path ] = array( $present, $present ? $value : null );
		}
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
