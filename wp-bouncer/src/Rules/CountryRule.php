<?php
/**
 * Blocks (or only admits) visitors from selected countries.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;
use WPBouncer\Geo\GeoProviderInterface;

defined( 'ABSPATH' ) || exit;

/**
 * Settings:
 * - enabled (bool)
 * - mode ("block"|"allow"): "block" refuses the listed countries; "allow"
 *   admits only the listed countries.
 * - countries (string[]): ISO 3166-1 alpha-2 codes.
 * - block_unknown (bool): refuse IPs the geo database can't place.
 * - scope ("site"|"login"): the whole site, or only wp-login.php, xmlrpc.php and wp-admin.
 */
final class CountryRule extends AbstractRule {

	public const ID = 'country';

	/**
	 * Country lookup.
	 *
	 * @var GeoProviderInterface
	 */
	private GeoProviderInterface $geo;

	/**
	 * Set up the CountryRule.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 * @param GeoProviderInterface $geo      Country lookup.
	 */
	public function __construct( array $settings, GeoProviderInterface $geo ) {
		parent::__construct( $settings );
		$this->geo = $geo;
	}

	/** {@inheritDoc} */
	public function id(): string {
		return self::ID;
	}

	/** {@inheritDoc} */
	public function is_enabled(): bool {
		// "allow" mode with an empty list would lock everyone out; treat that as off.
		if ( 'allow' === $this->setting( 'mode', 'block' ) && empty( $this->setting( 'countries', array() ) ) ) {
			return false;
		}
		return parent::is_enabled();
	}

	/**
	 * Inspect the request.
	 *
	 * @param Request $request Incoming request.
	 * @return Verdict|null A Verdict to refuse the request, or null to let it through.
	 */
	public function inspect( Request $request ): ?Verdict {
		if ( 'login' === $this->setting( 'scope', 'site' ) && ! ( $request->is_login() || $request->is_xmlrpc() || $request->is_admin_area() ) ) {
			return null;
		}

		// A request from the server itself has no geography. Skipping on the request
		// (not on a loopback IP) keeps a loopback proxy's visitors subject to
		// block_unknown, while health checks and WP-Cron pass.
		if ( $request->is_local() ) {
			return null;
		}

		$country = $this->geo->lookup( $request->ip() );

		if ( null === $country ) {
			return $this->setting( 'block_unknown', false ) ? $this->deny( 'Country could not be determined' ) : null;
		}

		$listed = in_array( $country, (array) $this->setting( 'countries', array() ), true );

		if ( 'allow' === $this->setting( 'mode', 'block' ) ) {
			return $listed ? null : $this->deny( sprintf( 'Country %s is not on the allow list', $country ) );
		}
		return $listed ? $this->deny( sprintf( 'Country %s is blocked', $country ) ) : null;
	}
}
