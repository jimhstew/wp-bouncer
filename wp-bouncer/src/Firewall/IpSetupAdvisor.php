<?php
/**
 * Spots IP-detection settings that don't match the server's real setup.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Firewall;

use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP (no WordPress calls). Given $_SERVER and the IP settings, returns
 * a list of findings that the admin notice turns into text and buttons.
 *
 * Each finding is an array with a 'code' and the arguments that code needs:
 *
 * - header_without_proxies: a header source is set with no usable trusted
 *   proxies, so the header is ignored. Args: peer, source, header_present.
 * - loopback_peer_with_forwarding: the source is REMOTE_ADDR but REMOTE_ADDR is
 *   a loopback or private address and a forwarding header arrived, so the
 *   plugin is probably behind a reverse proxy. Args: peer, header (a
 *   IpResolver::SOURCES key, or '' for the Forwarded header).
 * - broad_ranges_ignored: trusted proxy or allowlist entries too wide to be
 *   honoured. Args: entries.
 * - peer_not_in_proxies: a header source with proxies, a forwarding header is
 *   present, but REMOTE_ADDR isn't listed (the proxy's IP may have changed).
 *   Informational. Args: peer.
 */
final class IpSetupAdvisor {

	public const HEADER_WITHOUT_PROXIES = 'header_without_proxies';
	public const LOOPBACK_PEER          = 'loopback_peer_with_forwarding';
	public const BROAD_RANGES_IGNORED   = 'broad_ranges_ignored';
	public const PEER_NOT_IN_PROXIES    = 'peer_not_in_proxies';

	/**
	 * Check the setup.
	 *
	 * @param array<string, mixed> $server    $_SERVER.
	 * @param string               $source    Configured ip_source.
	 * @param string[]             $proxies   Configured trusted proxies (as stored).
	 * @param string[]             $allowlist Configured allowlist (as stored); only checked for broad ranges.
	 * @return array<int, array<string, mixed>> Findings, most important first.
	 */
	public function check( array $server, string $source, array $proxies, array $allowlist = array() ): array {
		$source    = isset( IpResolver::SOURCES[ $source ] ) ? $source : 'remote_addr';
		$peer      = trim( (string) ( $server['REMOTE_ADDR'] ?? '' ) );
		$peer      = IpUtils::is_valid( $peer ) ? $peer : '';
		$effective = IpUtils::without_broad( $proxies );
		$out       = array();

		if ( 'remote_addr' !== $source && empty( $effective ) ) {
			$out[] = array(
				'code'           => self::HEADER_WITHOUT_PROXIES,
				'peer'           => $peer,
				'source'         => $source,
				'header_present' => isset( $server[ IpResolver::SOURCES[ $source ] ] ),
			);
		}

		if ( 'remote_addr' === $source && '' !== $peer && ! IpUtils::is_public( $peer ) ) {
			$header = $this->forwarding_source( $server );
			if ( null !== $header ) {
				$out[] = array(
					'code'   => self::LOOPBACK_PEER,
					'peer'   => $peer,
					'header' => $header,
				);
			}
		}

		if ( 'remote_addr' !== $source && ! empty( $effective ) && '' !== $peer
			&& isset( $server[ IpResolver::SOURCES[ $source ] ] ) && ! IpUtils::matches_any( $peer, $effective ) ) {
			$out[] = array(
				'code' => self::PEER_NOT_IN_PROXIES,
				'peer' => $peer,
			);
		}

		$ignored = array_values( array_unique( array_merge( array_diff( $proxies, $effective ), array_diff( $allowlist, IpUtils::without_broad( $allowlist ) ) ) ) );
		if ( ! empty( $ignored ) ) {
			$out[] = array(
				'code'    => self::BROAD_RANGES_IGNORED,
				'entries' => array_map( 'strval', $ignored ),
			);
		}
		return $out;
	}

	/**
	 * Which forwarding header arrived, as an ip_source key.
	 *
	 * @param array<string, mixed> $server $_SERVER.
	 * @return string|null The source key, '' for a Forwarded header with no matching source, or null for none.
	 */
	private function forwarding_source( array $server ): ?string {
		foreach ( IpResolver::SOURCES as $key => $server_key ) {
			if ( 'remote_addr' !== $key && isset( $server[ $server_key ] ) ) {
				return $key;
			}
		}
		return isset( $server['HTTP_FORWARDED'] ) ? '' : null;
	}
}
