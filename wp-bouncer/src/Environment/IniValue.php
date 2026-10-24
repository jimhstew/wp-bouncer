<?php
/**
 * Reading php.ini values the way PHP itself does.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

defined( 'ABSPATH' ) || exit;

/**
 * Pure helpers. `ini_get()` returns strings such as "On", "1", "stdout" or
 * false (unknown directive); unparseable values are "unknown", never a warning.
 */
final class IniValue {

	/**
	 * Boolean directive.
	 *
	 * Like PHP: any non-zero number is true (so -1 is true), except zend.assertions,
	 * where -1 and 0 mean "off". "stdout" and "stderr" are values of display_errors only.
	 *
	 * @param string|false $raw       Value from ini_get().
	 * @param string       $directive Directive name, for the few that differ.
	 * @return bool|null Null when unknown.
	 */
	public static function flag( string|false $raw, string $directive = '' ): ?bool {
		if ( false === $raw ) {
			return null;
		}
		$v = strtolower( trim( $raw ) );
		if ( in_array( $v, array( 'on', 'true', 'yes' ), true ) ) {
			return true;
		}
		if ( in_array( $v, array( 'stdout', 'stderr' ), true ) ) {
			return 'display_errors' === $directive ? true : null;
		}
		if ( in_array( $v, array( '', 'off', 'false', 'no', 'none' ), true ) ) {
			return false;
		}
		if ( 1 === preg_match( '/^-?\d+$/', $v ) ) {
			return 'zend.assertions' === $directive ? (int) $v > 0 : 0 !== (int) $v;
		}
		return null;
	}

	/**
	 * Size directive such as "64M".
	 *
	 * @param string|false $raw Value from ini_get().
	 * @return int|null Bytes, -1 for unlimited, null when unknown.
	 */
	public static function bytes( string|false $raw ): ?int {
		if ( false === $raw ) {
			return null;
		}
		$v = strtolower( trim( $raw ) );
		if ( 1 !== preg_match( '/^(-?\d+)\s*([kmg]?)$/', $v, $m ) ) {
			return null;
		}
		$n = (int) $m[1];
		return match ( $m[2] ) {
			'k'     => $n * 1024,
			'm'     => $n * 1024 * 1024,
			'g'     => $n * 1024 * 1024 * 1024,
			default => $n,
		};
	}

	/**
	 * Integer directive.
	 *
	 * @param string|false $raw Value from ini_get().
	 * @return int|null Null when unknown.
	 */
	public static function int( string|false $raw ): ?int {
		if ( false === $raw || 1 !== preg_match( '/^\s*-?\d+\s*$/', $raw ) ) {
			return null;
		}
		return (int) trim( $raw );
	}
}
