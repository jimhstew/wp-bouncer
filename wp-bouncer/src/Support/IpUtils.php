<?php
/**
 * IP address helpers: validation, CIDR matching and fixed-width encoding.
 *
 * All comparisons work on a 16-byte representation where IPv4 addresses are
 * mapped into the IPv4-mapped IPv6 space (::ffff:a.b.c.d). That lets IPv4 and
 * IPv6 share one code path and one geo database column.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Static IP utilities. Pure PHP, no WordPress dependencies.
 */
final class IpUtils {

	/**
	 * Is the string a valid IPv4 or IPv6 address?
	 *
	 * @param string $ip Candidate address.
	 */
	public static function is_valid( string $ip ): bool {
		return false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Is the string a valid IPv6 address?
	 *
	 * @param string $ip Candidate address.
	 */
	public static function is_ipv6( string $ip ): bool {
		return false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
	}

	/**
	 * Is the string a single IP or a CIDR range (e.g. 10.0.0.0/8, 2001:db8::/32)?
	 *
	 * @param string $entry Candidate entry.
	 */
	public static function is_valid_range( string $entry ): bool {
		$entry = trim( $entry );
		if ( false === strpos( $entry, '/' ) ) {
			return self::is_valid( $entry );
		}
		list( $ip, $bits ) = explode( '/', $entry, 2 );
		if ( ! self::is_valid( $ip ) || '' === $bits || ! ctype_digit( $bits ) ) {
			return false;
		}
		return (int) $bits <= ( self::is_ipv6( $ip ) ? 128 : 32 );
	}

	/**
	 * Does $ip fall inside $range (a single IP or a CIDR block)?
	 *
	 * @param string $ip    Address to test.
	 * @param string $range Single IP or CIDR.
	 */
	public static function in_range( string $ip, string $range ): bool {
		$range = trim( $range );
		if ( ! self::is_valid( $ip ) || ! self::is_valid_range( $range ) ) {
			return false;
		}

		if ( false === strpos( $range, '/' ) ) {
			return self::to_binary16( $ip ) === self::to_binary16( $range );
		}

		list( $subnet, $bits ) = explode( '/', $range, 2 );
		$bits = (int) $bits;
		if ( ! self::is_ipv6( $subnet ) ) {
			$bits += 96; // IPv4 lives in the last 32 bits of the mapped form.
		}

		$ip_bin  = (string) self::to_binary16( $ip );
		$net_bin = (string) self::to_binary16( $subnet );

		$whole_bytes = intdiv( $bits, 8 );
		$extra_bits  = $bits % 8;

		if ( substr( $ip_bin, 0, $whole_bytes ) !== substr( $net_bin, 0, $whole_bytes ) ) {
			return false;
		}
		if ( 0 === $extra_bits ) {
			return true;
		}
		$mask = ( 0xFF << ( 8 - $extra_bits ) ) & 0xFF;
		return ( ord( $ip_bin[ $whole_bytes ] ) & $mask ) === ( ord( $net_bin[ $whole_bytes ] ) & $mask );
	}

	/**
	 * Does $ip match any entry in $ranges?
	 *
	 * @param string   $ip     Address to test.
	 * @param string[] $ranges Single IPs and/or CIDR blocks.
	 */
	public static function matches_any( string $ip, array $ranges ): bool {
		foreach ( $ranges as $range ) {
			if ( self::in_range( $ip, (string) $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Is the address a loopback address (127.0.0.0/8 or ::1)?
	 *
	 * @param string $ip Address to test.
	 */
	public static function is_loopback( string $ip ): bool {
		return self::matches_any( $ip, array( '127.0.0.0/8', '::1' ) );
	}

	/**
	 * Encode an address as 16 bytes (IPv4 mapped to ::ffff:0:0/96).
	 *
	 * @param string $ip Address.
	 * @return string|null Binary string, or null when invalid.
	 */
	public static function to_binary16( string $ip ): ?string {
		if ( ! self::is_valid( $ip ) ) {
			return null;
		}
		$packed = inet_pton( $ip );
		if ( 4 === strlen( $packed ) ) {
			return str_repeat( "\0", 10 ) . "\xff\xff" . $packed;
		}
		return $packed;
	}

	/**
	 * Hex form of to_binary16(). Fixed width and lowercase, so string order
	 * equals address order. The geo table stores ranges this way.
	 *
	 * @param string $ip Address.
	 * @return string|null 32 lowercase hex chars, or null when invalid.
	 */
	public static function to_hex16( string $ip ): ?string {
		$bin = self::to_binary16( $ip );
		return null === $bin ? null : bin2hex( $bin );
	}
}
