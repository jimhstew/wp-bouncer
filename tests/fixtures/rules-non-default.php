<?php
/**
 * A settings fixture that differs from the defaults in every rule and in every field of every rule.
 *
 * Used by the Rules tab round-trip tests (integration and e2e): saving the Rules form unchanged must
 * leave exactly this stored. Pass it through Settings::sanitize( array_replace_recursive( defaults, this ) ).
 *
 * @package WPBouncer\Tests
 */

return array(
	'rules' => array(
		'ip_blocklist'     => array( 'enabled' => false, 'ips' => array( '198.51.100.7', '192.0.2.0/24' ) ),
		'user_agent'       => array( 'enabled' => false, 'block_empty' => false, 'patterns' => array( 'badbot', '/^evil\\/\\d+/i' ) ),
		'country'          => array( 'enabled' => true, 'mode' => 'block', 'countries' => array( 'DE', 'FR' ), 'block_unknown' => false, 'scope' => 'login' ),
		'xmlrpc'           => array( 'enabled' => false, 'mode' => 'block_abuse' ),
		'login_lockout'    => array( 'enabled' => false, 'max_attempts' => 7, 'window_minutes' => 20, 'lockout_minutes' => 90, 'banned_usernames' => array( 'mallory', 'eve' ), 'generic_errors' => false ),
		'rate_limit'       => array( 'enabled' => true, 'max_requests' => 500, 'window_seconds' => 120, 'ban_minutes' => 30 ),
		'waf'              => array( 'enabled' => false, 'sqli' => false, 'xss' => false, 'traversal' => false, 'code_injection' => false, 'inspect_json' => false, 'excluded_params' => array( 'content', 'html' ) ),
		'user_enumeration' => array( 'enabled' => false, 'block_author_scan' => false, 'block_rest_users' => false ),
		'sensitive_files'  => array( 'enabled' => false, 'ban_minutes' => 15, 'extra_paths' => array( '/old-site/' ) ),
		'not_found'        => array( 'enabled' => false, 'max_404' => 50, 'window_seconds' => 120, 'ban_minutes' => 5, 'ignore_crawlers' => false ),
		'uploads_php'      => array( 'enabled' => false, 'htaccess' => false, 'check_uploads' => false ),
	),
);
