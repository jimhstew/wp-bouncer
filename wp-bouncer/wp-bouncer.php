<?php
/**
 * Plugin Name:       WP Bouncer
 * Plugin URI:        https://github.com/jimhstew/wp-bouncer
 * Update URI:        https://github.com/jimhstew/wp-bouncer
 * Description:       A self-contained firewall that turns away unwanted visitors at the door: IP and country blocking, bad user-agents, brute-force login lockouts, XML-RPC blocking, rate limiting, user-enumeration protection and a lightweight WAF. No cloud service, no subscription.
 * Version:           1.1.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            WP Bouncer contributors
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-bouncer
 * Domain Path:       /languages
 *
 * @package WPBouncer
 */

defined( 'ABSPATH' ) || exit;

define( 'WP_BOUNCER_VERSION', '1.1.0' );
define( 'WP_BOUNCER_FILE', __FILE__ );
define( 'WP_BOUNCER_DIR', __DIR__ );

require_once __DIR__ . '/src/Autoloader.php';
\WPBouncer\Autoloader::register( __DIR__ . '/src' );

\WPBouncer\Plugin::boot( __FILE__ );
