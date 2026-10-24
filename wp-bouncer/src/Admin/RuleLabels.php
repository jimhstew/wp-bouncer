<?php
/**
 * Translated text for the rule screens.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Every title, description, category name, warning and summary the rule
 * screens show. Plain text: views escape it.
 */
final class RuleLabels {

	/**
	 * Rule id => [ title, one-line description ].
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function rules(): array {
		return array(
			'ip_blocklist'     => array( __( 'IP blocklist', 'wp-bouncer' ), __( 'Refuse specific IP addresses and CIDR ranges.', 'wp-bouncer' ) ),
			'user_agent'       => array( __( 'User-Agent filter', 'wp-bouncer' ), __( 'Refuse known attack tools and requests with no User-Agent.', 'wp-bouncer' ) ),
			'country'          => array( __( 'Country blocking', 'wp-bouncer' ), __( 'Refuse (or only admit) visitors from chosen countries.', 'wp-bouncer' ) ),
			'xmlrpc'           => array( __( 'XML-RPC blocking', 'wp-bouncer' ), __( 'Close xmlrpc.php, a common brute-force and pingback-abuse target.', 'wp-bouncer' ) ),
			'login_lockout'    => array( __( 'Login lockout', 'wp-bouncer' ), __( 'Lock out IPs after repeated failed logins.', 'wp-bouncer' ) ),
			'rate_limit'       => array( __( 'Rate limiting', 'wp-bouncer' ), __( 'Temporarily ban IPs that make too many requests.', 'wp-bouncer' ) ),
			'waf'              => array( __( 'Web application firewall', 'wp-bouncer' ), __( 'Refuse SQL injection, XSS, path traversal and code injection payloads.', 'wp-bouncer' ) ),
			'user_enumeration' => array( __( 'User enumeration', 'wp-bouncer' ), __( 'Stop anonymous visitors from harvesting usernames.', 'wp-bouncer' ) ),
			'sensitive_files'  => array( __( 'Sensitive-file probes', 'wp-bouncer' ), __( 'Ban IPs that look for .env, .git, backups, database dumps and web shells.', 'wp-bouncer' ) ),
			'not_found'        => array( __( '404 flood', 'wp-bouncer' ), __( 'Ban IPs that hit many "not found" pages, as vulnerability scanners do.', 'wp-bouncer' ) ),
			'uploads_php'      => array( __( 'No PHP in uploads', 'wp-bouncer' ), __( 'Stop scripts running from the uploads folder, and refuse uploads that are scripts.', 'wp-bouncer' ) ),
		);
	}

	/**
	 * Category slug => [ name, one-line description ].
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function categories(): array {
		return array(
			'block-lists'        => array( __( 'Block lists', 'wp-bouncer' ), __( 'Which visitors never get in.', 'wp-bouncer' ) ),
			'login-accounts'     => array( __( 'Login and accounts', 'wp-bouncer' ), __( 'Protecting sign-in and usernames.', 'wp-bouncer' ) ),
			'scanners-floods'    => array( __( 'Scanners and floods', 'wp-bouncer' ), __( 'Temporary bans for probing and too many requests.', 'wp-bouncer' ) ),
			'payloads-hardening' => array( __( 'Attack payloads and hardening', 'wp-bouncer' ), __( 'Malicious request content and script uploads.', 'wp-bouncer' ) ),
			RuleCatalog::OTHER   => array( __( 'Other', 'wp-bouncer' ), __( 'Rules added by other plugins.', 'wp-bouncer' ) ),
		);
	}

	/**
	 * The warning or hint for a RuleStatus reason, as shown on the rule's card.
	 *
	 * The link, if any, leads to where the problem is fixed. Reasons fixed in the rule's own
	 * settings have no link.
	 *
	 * @param string $code RuleStatus reason code.
	 * @return array{text: string, link_text: string, link_url: string}
	 */
	public static function reason( string $code ): array {
		$text = '';
		$link = array( '', '' );
		switch ( $code ) {
			case RuleStatus::NO_GEO_DB:
				$text = __( 'No geo database is loaded, so the country of a visitor can\'t be told.', 'wp-bouncer' );
				$link = array( __( 'Import one under Tools', 'wp-bouncer' ), AdminController::url( 'tools' ) );
				break;
			case RuleStatus::GEO_HEADER_UNTRUSTED:
				$text = __( 'Paused: the country comes from a request header, but no trusted proxy is listed, so the header could be forged.', 'wp-bouncer' );
				$link = array( __( 'General → Trusted proxies', 'wp-bouncer' ), AdminController::url( 'general' ) . '#wpb-proxies' );
				break;
			case RuleStatus::NO_COUNTRIES:
				$text = __( 'No countries are chosen, so this rule blocks nobody.', 'wp-bouncer' );
				$link = array( __( 'Choose countries', 'wp-bouncer' ), AdminController::url( 'countries' ) );
				break;
			case RuleStatus::ALLOW_LIST_EMPTY:
				$text = __( '"Only allow" mode has no countries chosen, so the rule is not applied.', 'wp-bouncer' );
				$link = array( __( 'Choose countries', 'wp-bouncer' ), AdminController::url( 'countries' ) );
				break;
			case RuleStatus::UPLOADS_BROKEN:
				$text = __( 'The .htaccess block was removed because your server failed to serve uploads with it. Uploads are not protected.', 'wp-bouncer' );
				break;
			case RuleStatus::UPLOADS_WRITE_FAILED:
				$text = __( 'The .htaccess block could not be written (the folder may not be writable).', 'wp-bouncer' );
				break;
			case RuleStatus::UPLOADS_UNPROTECTED:
				$text = __( 'The last server test found that scripts can still run from the uploads folder.', 'wp-bouncer' );
				break;
			case RuleStatus::SETUP_COUNTRY:
				$text = __( 'import a geo database first, or the rule can\'t tell where visitors are.', 'wp-bouncer' );
				$link = array( __( 'Import one under Tools', 'wp-bouncer' ), AdminController::url( 'tools' ) );
				break;
			case RuleStatus::SETUP_RATE_LIMIT:
				$text = __( 'without a persistent object cache (Redis or Memcached) every counted request writes to the database. Read the note in the settings below.', 'wp-bouncer' );
				break;
		}
		return array(
			'text'      => $text,
			'link_text' => $link[0],
			'link_url'  => $link[1],
		);
	}

	/**
	 * The screen-wide notice for a reason, or null when the reason shows only on the rule's card.
	 *
	 * @param string $code RuleStatus reason code.
	 * @return array{type: string, text: string, link_text: string, link_url: string}|null
	 */
	public static function notice( string $code ): ?array {
		switch ( $code ) {
			case RuleStatus::NO_GEO_DB:
				return array(
					'type'      => 'error',
					'text'      => __( 'Country blocking is on but no geo database is loaded, so it can\'t identify any country.', 'wp-bouncer' ),
					'link_text' => __( 'Import one under Tools', 'wp-bouncer' ),
					'link_url'  => AdminController::url( 'tools' ),
				);
			case RuleStatus::GEO_HEADER_UNTRUSTED:
				return array(
					'type'      => 'warning',
					'text'      => __( 'Country blocking is paused: it reads the country from a request header, but no trusted proxy is listed, so the header could be forged. Add your proxy under Trusted proxies, or import a geo database under Tools.', 'wp-bouncer' ),
					'link_text' => __( 'General → Trusted proxies', 'wp-bouncer' ),
					'link_url'  => AdminController::url( 'general' ) . '#wpb-proxies',
				);
			case RuleStatus::UPLOADS_BROKEN:
				return array(
					'type'      => 'error',
					'text'      => __( 'WP Bouncer removed its block from wp-content/uploads/.htaccess: with it in place, your server answered uploaded files (images too) with an error, probably because it doesn\'t allow access rules in .htaccess. Uploads are not protected.', 'wp-bouncer' ),
					'link_text' => __( 'Go to No PHP in uploads', 'wp-bouncer' ),
					'link_url'  => AdminController::rule_url( 'uploads_php' ),
				);
			case RuleStatus::UPLOADS_WRITE_FAILED:
				return array(
					'type'      => 'warning',
					'text'      => __( 'WP Bouncer could not write its block to wp-content/uploads/.htaccess (the folder may not be writable).', 'wp-bouncer' ),
					'link_text' => __( 'Go to No PHP in uploads', 'wp-bouncer' ),
					'link_url'  => AdminController::rule_url( 'uploads_php' ),
				);
		}
		return null;
	}

	/**
	 * "2 of 3 rules on".
	 *
	 * @param int $on    Rules switched on.
	 * @param int $total Rules in the group.
	 */
	public static function summary( int $on, int $total ): string {
		return sprintf(
			/* translators: 1: rules switched on, 2: rules in this category. */
			_n( '%1$s of %2$s rule on', '%1$s of %2$s rules on', $total, 'wp-bouncer' ),
			number_format_i18n( $on ),
			number_format_i18n( $total )
		);
	}

	/**
	 * "1 needs attention".
	 *
	 * @param int $attention Rules that need attention.
	 */
	public static function attention( int $attention ): string {
		return sprintf(
			/* translators: %s: number of rules that need attention. */
			_n( '%s needs attention', '%s need attention', $attention, 'wp-bouncer' ),
			number_format_i18n( $attention )
		);
	}

	/**
	 * One sentence about what the country rule does now.
	 *
	 * @param array<string, mixed> $rule The country rule's settings.
	 */
	public static function country_summary( array $rule ): string {
		$n = count( (array) ( $rule['countries'] ?? array() ) );
		if ( 0 === $n ) {
			return __( 'No countries chosen.', 'wp-bouncer' );
		}
		$allow = 'allow' === ( $rule['mode'] ?? 'block' );
		$login = 'login' === ( $rule['scope'] ?? 'site' );
		$count = number_format_i18n( $n );
		if ( $allow && $login ) {
			/* translators: %s: number of countries. */
			$text = _n( 'Admitting only %s country on login pages.', 'Admitting only %s countries on login pages.', $n, 'wp-bouncer' );
		} elseif ( $allow ) {
			/* translators: %s: number of countries. */
			$text = _n( 'Admitting only %s country on the whole site.', 'Admitting only %s countries on the whole site.', $n, 'wp-bouncer' );
		} elseif ( $login ) {
			/* translators: %s: number of countries. */
			$text = _n( 'Blocking %s country on login pages.', 'Blocking %s countries on login pages.', $n, 'wp-bouncer' );
		} else {
			/* translators: %s: number of countries. */
			$text = _n( 'Blocking %s country on the whole site.', 'Blocking %s countries on the whole site.', $n, 'wp-bouncer' );
		}
		return sprintf( $text, $count );
	}
}
