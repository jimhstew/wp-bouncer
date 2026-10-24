<?php
/**
 * The key a client is counted under.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Maps a client address to the subject that counters and lockouts use.
 *
 * IPv4 (and IPv4-mapped IPv6) is counted per address. IPv6 is counted per
 * network, by default a /64, because one subscriber normally holds a whole
 * /64 and could otherwise rotate addresses to dodge every threshold (RT-07).
 * Set WP_BOUNCER_IPV6_PREFIX in wp-config.php (48 to 128) to change the width;
 * 128 goes back to one counter per address.
 *
 * Addresses that embed an IPv4 address use it, so an attacker can't get many keys for
 * one IPv4 client: IPv4-mapped (::ffff:a.b.c.d), IPv4-translated (::ffff:0:a.b.c.d),
 * NAT64 (64:ff9b::/96) and 6to4 (2002::/16). Teredo (2001::/32) is not unwrapped: it
 * embeds an obfuscated client address and a relay, and is rare, so it is keyed as IPv6.
 *
 * Log rows keep the full address; only counters use the subject.
 * Pure PHP: no WordPress calls.
 */
final class CounterSubject {

	public const DEFAULT_PREFIX = 64;

	/** Narrowest allowed network: wider would let one noisy host lock out a large allocation. */
	public const MIN_PREFIX = 48;

	/** The configured IPv6 prefix length. */
	public static function configured_prefix(): int {
		if ( defined( 'WP_BOUNCER_IPV6_PREFIX' ) ) {
			$prefix = filter_var( constant( 'WP_BOUNCER_IPV6_PREFIX' ), FILTER_VALIDATE_INT );
			if ( false !== $prefix && $prefix >= self::MIN_PREFIX && $prefix <= 128 ) {
				return $prefix;
			}
		}
		return self::DEFAULT_PREFIX;
	}

	/**
	 * The counter subject for an address.
	 *
	 * @param string   $ip        Client address, or a non-address key such as "rejected:<proxy>".
	 * @param int|null $v6_prefix IPv6 prefix length; null for the configured one.
	 * @return string '' for an address that must not be counted (loopback, unspecified),
	 *                the dotted IPv4 for IPv4, "<network>/<prefix>" for IPv6, or the
	 *                input unchanged when it isn't an address.
	 */
	public static function of( string $ip, ?int $v6_prefix = null ): string {
		$ip = trim( $ip );
		if ( '' === $ip ) {
			return '';
		}
		if ( ! IpUtils::is_valid( $ip ) ) {
			return $ip;
		}
		$canonical = IpUtils::canonical( $ip );
		if ( IpUtils::is_loopback( $canonical ) || IpUtils::is_unspecified( $canonical ) ) {
			return '';
		}
		if ( false === strpos( $canonical, ':' ) ) {
			return $canonical;
		}

		$packed = (string) inet_pton( $canonical );
		$v4     = self::embedded_ipv4( $packed );
		// A translated address whose IPv4 isn't a public client (private, loopback, ...) stays an IPv6 key.
		if ( null !== $v4 && IpUtils::is_public( $v4 ) ) {
			return self::of( $v4, $v6_prefix );
		}

		$prefix = min( 128, max( self::MIN_PREFIX, $v6_prefix ?? self::configured_prefix() ) );
		$mask   = str_repeat( "\xff", intdiv( $prefix, 8 ) );
		if ( 0 !== $prefix % 8 ) {
			$mask .= chr( ( 0xff << ( 8 - $prefix % 8 ) ) & 0xff );
		}
		$mask = str_pad( $mask, 16, "\0" );
		return inet_ntop( $packed & $mask ) . '/' . $prefix;
	}

	/**
	 * The IPv4 address inside a 16-byte IPv6 address, for the translation forms.
	 *
	 * @param string $packed 16 bytes.
	 * @return string|null Dotted IPv4, or null for an ordinary IPv6 address.
	 */
	private static function embedded_ipv4( string $packed ): ?string {
		$head12 = substr( $packed, 0, 12 );
		$nat64  = "\0\x64\xff\x9b" . str_repeat( "\0", 8 ); // 64:ff9b::/96.
		$xlat   = str_repeat( "\0", 8 ) . "\xff\xff\0\0";   // ::ffff:0:0:0/96, IPv4-translated.
		if ( $head12 === $nat64 || $head12 === $xlat ) {
			return inet_ntop( substr( $packed, 12, 4 ) );
		}
		// 2002::/16 (6to4): the IPv4 address is bytes 2 to 5.
		if ( "\x20\x02" === substr( $packed, 0, 2 ) ) {
			return inet_ntop( substr( $packed, 2, 4 ) );
		}
		return null;
	}
}
