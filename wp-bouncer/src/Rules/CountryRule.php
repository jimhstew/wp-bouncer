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
	 * Paused: the only country source is an untrusted header, so there is nothing to decide on.
	 *
	 * @var bool
	 */
	private bool $paused;

	/**
	 * Set up the CountryRule.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 * @param GeoProviderInterface $geo      Country lookup.
	 * @param bool                 $paused   Skip the rule (no verdicts at all).
	 */
	public function __construct( array $settings, GeoProviderInterface $geo, bool $paused = false ) {
		parent::__construct( $settings );
		$this->geo    = $geo;
		$this->paused = $paused;
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
		if ( $this->paused ) {
			return null;
		}
		if ( $this->login_only() && ! ( $request->is_login() || $request->is_xmlrpc() || $request->is_admin_area() ) ) {
			return null;
		}
		return $this->decide( $request );
	}

	/**
	 * Does the login scope apply (enabled, not paused, scope "login")?
	 *
	 * Used to enforce the decision on authentication paths the request-path check cannot see
	 * (REST application passwords, custom login URLs).
	 */
	public function guards_authentication(): bool {
		return ! $this->paused && $this->is_enabled() && $this->login_only();
	}

	/**
	 * The country decision for a request, whatever its path.
	 *
	 * @param Request $request Incoming request.
	 * @return Verdict|null A Verdict to refuse the request, or null to let it through.
	 */
	public function decide( Request $request ): ?Verdict {
		if ( $this->paused ) {
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

		if ( ! $this->refuses( $country ) ) {
			return null;
		}
		if ( 'allow' === $this->setting( 'mode', 'block' ) ) {
			return $this->deny( sprintf( 'Country %s is not on the allow list', $country ) );
		}
		return $this->deny( sprintf( 'Country %s is blocked', $country ) );
	}

	/**
	 * Would visitors from this country be refused (rule on and not paused)?
	 *
	 * The same test the firewall uses. Ignores monitor mode, the IP allowlist and the scope;
	 * see login_only() for the scope.
	 *
	 * @param string $country ISO 3166-1 alpha-2 code.
	 */
	public function blocks_country( string $country ): bool {
		return ! $this->paused && $this->is_enabled() && $this->refuses( $country );
	}

	/** Does the rule apply to the login and admin paths only? */
	public function login_only(): bool {
		return 'login' === $this->setting( 'scope', 'site' );
	}

	/**
	 * Is the country refused by the list and mode?
	 *
	 * @param string $country ISO 3166-1 alpha-2 code.
	 */
	private function refuses( string $country ): bool {
		$listed = in_array( $country, (array) $this->setting( 'countries', array() ), true );
		return 'allow' === $this->setting( 'mode', 'block' ) ? ! $listed : $listed;
	}
}
