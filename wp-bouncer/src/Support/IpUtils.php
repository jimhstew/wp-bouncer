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
		$bits                  = (int) $bits;
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
	 * Ranges that are never a real client on the public internet: this-network
	 * and unspecified, loopback, RFC 1918, link-local, CGNAT, and the IPv6
	 * equivalents (::/96 covers :: and ::1, fe80::/10, fc00::/7).
	 *
	 * An explicit list rather than FILTER_FLAG_NO_RES_RANGE, whose meaning varies
	 * between PHP versions and which would reject the documentation ranges
	 * (192.0.2/24, 198.51.100/24, 203.0.113/24) used as client IPs in tests.
	 * IPv4-mapped IPv6 forms are covered because matching is done on 16 bytes.
	 */
	private const NON_PUBLIC = array(
		'0.0.0.0/8',
		'10.0.0.0/8',
		'100.64.0.0/10',
		'127.0.0.0/8',
		'169.254.0.0/16',
		'172.16.0.0/12',
		'192.168.0.0/16',
		'::/96',
		'fe80::/10',
		'fc00::/7',
	);

	/**
	 * Canonical text form of an address, with IPv4-mapped IPv6 unmapped.
	 *
	 * For classification only; callers should not store the result in place
	 * of the address they were given.
	 *
	 * @param string $ip Address.
	 * @return string The canonical form, or $ip unchanged when it is not valid.
	 */
	public static function canonical( string $ip ): string {
		if ( ! self::is_valid( $ip ) ) {
			return $ip;
		}
		$packed = inet_pton( $ip );
		if ( 16 === strlen( $packed ) && str_repeat( "\0", 10 ) . "\xff\xff" === substr( $packed, 0, 12 ) ) {
			$packed = substr( $packed, 12 );
		}
		return (string) inet_ntop( $packed );
	}

	/**
	 * Is the address a plausible public client address?
	 *
	 * False for anything invalid, unspecified, loopback, private, link-local,
	 * CGNAT or unique-local, including their IPv4-mapped forms.
	 *
	 * @param string $ip Address.
	 */
	public static function is_public( string $ip ): bool {
		if ( ! self::is_valid( $ip ) ) {
			return false;
		}
		return ! self::matches_any( self::canonical( $ip ), self::NON_PUBLIC );
	}

	/**
	 * Is the address unspecified (0.0.0.0 or ::)?
	 *
	 * @param string $ip Address.
	 */
	public static function is_unspecified( string $ip ): bool {
		return self::is_valid( $ip ) && ( self::in_range( $ip, '0.0.0.0' ) || self::in_range( $ip, '::' ) );
	}

	/**
	 * Is the CIDR so wide that listing it would trust or exempt a large part of the internet?
	 *
	 * True for an IPv4 prefix shorter than /8, an IPv6 prefix shorter than /16, or an
	 * IPv6 range in the first 80 zero bits (IPv4-scale space) shorter than /104.
	 * A single address (no slash) is never broad.
	 *
	 * @param string $cidr Entry such as 10.0.0.0/8.
	 */
	public static function is_broad_range( string $cidr ): bool {
		$cidr = trim( $cidr );
		if ( false === strpos( $cidr, '/' ) || ! self::is_valid_range( $cidr ) ) {
			return false;
		}
		list( $ip, $bits ) = explode( '/', $cidr, 2 );
		if ( ! self::is_ipv6( $ip ) ) {
			return (int) $bits < 8;
		}
		// An IPv6 range whose first 80 bits are zero (::/80, ::ffff:0:0/96) is the
		// IPv4 space in disguise, so it is held to the IPv4 limit: /8 inside ::ffff:0:0/96.
		// Does the range overlap ::/80? Only the bits inside the prefix count, so the
		// address is not trusted as written (0:0:0:0:1::/64 covers all of that space).
		$packed  = (string) inet_pton( $ip );
		$checked = min( (int) $bits, 80 );
		$overlap = true;
		for ( $i = 0; $i < $checked && $overlap; $i += 8 ) {
			$keep    = min( 8, $checked - $i );
			$mask    = ( 0xFF << ( 8 - $keep ) ) & 0xFF;
			$overlap = 0 === ( ord( $packed[ intdiv( $i, 8 ) ] ) & $mask );
		}
		if ( $overlap ) {
			return (int) $bits < 104;
		}
		return (int) $bits < 16;
	}

	/**
	 * Drop over-broad entries from a list of IPs and CIDRs.
	 *
	 * @param string[] $entries Entries.
	 * @return string[] Entries that are not broad, in order.
	 */
	public static function without_broad( array $entries ): array {
		return array_values(
			array_filter(
				array_map( 'strval', $entries ),
				static function ( string $entry ): bool {
					return ! self::is_broad_range( $entry );
				}
			)
		);
	}

	/**
	 * May bans, lockouts and counters be kept for this address?
	 *
	 * Not for invalid, loopback or unspecified addresses, not for a trusted
	 * proxy (banning it would refuse everyone behind it), and not while the
	 * client address can't be told apart from a shared proxy.
	 *
	 * @param string   $ip                Resolved client IP.
	 * @param string[] $trusted_proxies   Effective trusted proxies.
	 * @param bool     $fallback_suspends True while the header-IP fallback is active.
	 */
	public static function is_bannable( string $ip, array $trusted_proxies, bool $fallback_suspends ): bool {
		if ( $fallback_suspends || ! self::is_valid( $ip ) || self::is_loopback( $ip ) || self::is_unspecified( $ip ) ) {
			return false;
		}
		return ! self::matches_any( $ip, $trusted_proxies );
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
