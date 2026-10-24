<?php
/**
 * Blocks IPs and CIDR ranges the admin has listed.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;
use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Settings:
 * - enabled (bool)
 * - ips (string[]): single addresses or CIDR blocks, IPv4 or IPv6.
 */
final class IpBlocklistRule extends AbstractRule {

	public const ID = 'ip_blocklist';

	/** {@inheritDoc} */
	public function id(): string {
		return self::ID;
	}

	/**
	 * Inspect the request.
	 *
	 * @param Request $request Incoming request.
	 * @return Verdict|null A Verdict to refuse the request, or null to let it through.
	 */
	public function inspect( Request $request ): ?Verdict {
		$ip = $request->ip();
		foreach ( (array) $this->setting( 'ips', array() ) as $range ) {
			if ( IpUtils::in_range( $ip, (string) $range ) ) {
				return $this->deny( sprintf( 'IP matches blocklist entry %s', $range ) );
			}
		}
		return null;
	}
}
