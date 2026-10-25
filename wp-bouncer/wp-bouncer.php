<?php
/**
 * Plugin Name:       WP Bouncer
 * Plugin URI:        https://github.com/jimhstew/wp-bouncer
 * Update URI:        https://github.com/jimhstew/wp-bouncer
 * Description:       A self-contained firewall that turns away unwanted visitors at the door: IP and country blocking, bad user-agents, brute-force login lockouts, XML-RPC blocking, rate limiting, user-enumeration protection, a lightweight WAF, bans for vulnerability scanners, no PHP in uploads, and email alerts for new admins and plugin changes. No cloud service, no subscription.
 * Version:           1.2.1
 * Requires at least: 7.0
 * Requires PHP:      8.3
 * Author:            WP Bouncer contributors
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-bouncer
 * Domain Path:       /languages
 *
 * @package WPBouncer
 */

defined( 'ABSPATH' ) || exit;

define( 'WP_BOUNCER_VERSION', '1.2.1' );
define( 'WP_BOUNCER_FILE', __FILE__ );
define( 'WP_BOUNCER_DIR', __DIR__ );

// Keep this file free of syntax newer than PHP 5.3 so that, on an unsupported PHP,
// it reaches the check below and shows a notice instead of a parse error.
define( 'WP_BOUNCER_MIN_PHP', '8.3' );
define( 'WP_BOUNCER_MIN_WP', '7.0' );

// Pre-release suffixes ("7.0-RC1") are ignored so a release candidate of the minimum passes.
if ( version_compare( preg_replace( '/-.*$/', '', PHP_VERSION ), WP_BOUNCER_MIN_PHP, '<' ) ) {
	// Too old to parse the rest of the plugin: only say so. Core will not auto-update into this.
	/**
	 * Tell admins why the plugin did not start.
	 *
	 * @return void
	 */
	function wp_bouncer_requirements_notice() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		printf(
			'<div class="notice notice-error"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: 1: required PHP version, 2: required WordPress version. */
					__( 'WP Bouncer is not running: it needs PHP %1$s or newer and WordPress %2$s or newer.', 'wp-bouncer' ),
					WP_BOUNCER_MIN_PHP,
					WP_BOUNCER_MIN_WP
				)
			)
		);
	}
	add_action( 'admin_notices', 'wp_bouncer_requirements_notice' );
	add_action( 'network_admin_notices', 'wp_bouncer_requirements_notice' );
	return;
}

require_once __DIR__ . '/src/Autoloader.php';
\WPBouncer\Autoloader::register( __DIR__ . '/src' );

if ( version_compare( preg_replace( '/-.*$/', '', $GLOBALS['wp_version'] ), WP_BOUNCER_MIN_WP, '<' ) ) {
	// PHP is fine but WordPress is too old (an automatic update from 1.1.x can get here).
	// No firewall, but keep the updater so a fixed release can arrive, and tell the admin.
	$wp_bouncer_guard = new \WPBouncer\Update\OldWordPressGuard( __FILE__, $GLOBALS['wp_version'], WP_BOUNCER_MIN_WP );
	$wp_bouncer_guard->register();
	unset( $wp_bouncer_guard );
	return;
}

// Once WordPress is new enough again, a future recurrence is reported afresh.
add_action( 'admin_init', 'WPBouncer\\Update\\OldWordPressGuard::reset' );

\WPBouncer\Plugin::boot( __FILE__ );
