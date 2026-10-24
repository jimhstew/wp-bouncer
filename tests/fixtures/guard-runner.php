<?php
/**
 * Loads wp-bouncer.php with stubbed WordPress functions and a chosen $wp_version,
 * then prints which hooks it registered and whether the plugin booted.
 *
 * Usage: php guard-runner.php <wp_version>
 *
 * @package WPBouncer\Tests
 */

define( 'ABSPATH', __DIR__ . '/' );
$GLOBALS['wp_version'] = $argv[1];
$hooks                 = array();
$callbacks             = array();

define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );

function add_action( $hook, $callback = null ) {
	$GLOBALS['hooks'][]     = $hook;
	$GLOBALS['callbacks'][] = array( $hook, $callback );
}
function add_filter( $hook ) {
	$GLOBALS['hooks'][] = $hook;
}
function wp_parse_url( $url, $component = -1 ) {
	return parse_url( $url, $component );
}
function get_site_option() {
	return false;
}
function wp_next_scheduled() {
	return false;
}
function wp_schedule_single_event( $time, $hook ) {
	$GLOBALS['hooks'][] = 'scheduled:' . $hook;
}
function register_activation_hook() {
	$GLOBALS['hooks'][] = 'booted';
}
function register_deactivation_hook() {}
function current_user_can() {
	return true;
}
function __( $text ) {
	return $text;
}
function esc_html( $text ) {
	return $text;
}

try {
	require dirname( __DIR__, 2 ) . '/wp-bouncer/wp-bouncer.php';
} catch ( \Throwable $e ) { // phpcs:ignore -- the stubs are too thin for a real boot; reaching Plugin is the signal.
	$GLOBALS['hooks'][] = 'boot-attempted';
}

ob_start();
if ( function_exists( 'wp_bouncer_requirements_notice' ) ) {
	wp_bouncer_requirements_notice();
}
foreach ( $GLOBALS['callbacks'] as $pair ) {
	if ( 'admin_notices' === $pair[0] && is_array( $pair[1] ) ) {
		call_user_func( $pair[1] );
	}
}
echo json_encode(
	array(
		'hooks'  => $GLOBALS['hooks'],
		'booted' => class_exists( 'WPBouncer\Plugin', false ),
		'notice' => ob_get_clean(),
	)
);
