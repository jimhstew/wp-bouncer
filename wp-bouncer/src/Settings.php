<?php
/**
 * Plugin settings: defaults, access and sanitisation.
 *
 * @package WPBouncer
 */

namespace WPBouncer;

use WPBouncer\Firewall\IpResolver;
use WPBouncer\Geo\Countries;
use WPBouncer\Rules\UserAgentRule;
use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * All settings live in one option (wp_bouncer_settings) as a nested array.
 * Each rule's settings are under rules.<rule id>, and every rule has its own
 * "enabled" switch.
 *
 * The sanitize() and apply_form() methods are pure PHP, so they are unit-tested directly.
 */
final class Settings {

	/** Longest automatic ban or lockout, in minutes (24 hours). Longer blocks belong in the IP blocklist. */
	public const MAX_BAN_MINUTES = 1440;

	public const OPTION = 'wp_bouncer_settings';

	/** Firewall modes. */
	public const MODE_ENFORCE = 'enforce';
	public const MODE_MONITOR = 'monitor';

	/**
	 * Which settings each admin tab owns. Saving a tab only replaces these
	 * keys, so a checkbox left unticked on one tab can't clear settings
	 * that belong to another tab.
	 */
	public const TAB_FIELDS = array(
		'general'   => array( 'mode', 'ip_source', 'trusted_proxies', 'allowlist', 'log_retention_days', 'block_message', 'geo_source', 'geo_header', 'alerts' ),
		'rules'     => array( 'rules.ip_blocklist', 'rules.user_agent', 'rules.xmlrpc', 'rules.login_lockout', 'rules.rate_limit', 'rules.waf', 'rules.user_enumeration', 'rules.sensitive_files', 'rules.not_found', 'rules.uploads_php' ),
		'countries' => array( 'rules.country' ),
		'traffic'   => array( 'traffic' ),
	);

	/**
	 * Settings values.
	 *
	 * @var array<string, mixed>
	 */
	private array $values;

	/**
	 * Set up the Settings.
	 *
	 * @param array<string, mixed> $stored Raw option value (may be partial or empty).
	 */
	public function __construct( array $stored = array() ) {
		$this->values = self::merge_defaults( $stored );
	}

	/**
	 * Load from the WordPress option.
	 */
	public static function load(): self {
		$stored = get_option( self::OPTION, array() );
		return new self( is_array( $stored ) ? $stored : array() );
	}

	/**
	 * Factory defaults. Conservative: everything that can't lock out real
	 * visitors is on; country blocking and rate limiting are off until configured.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults(): array {
		return array(
			'mode'               => self::MODE_ENFORCE,
			'ip_source'          => 'remote_addr',
			'trusted_proxies'    => array(),
			'allowlist'          => array(),
			'log_retention_days' => 30,
			'block_message'      => 'Sorry, your request has been blocked by this site\'s security policy.',
			'geo_source'         => 'database',
			'geo_header'         => 'CF-IPCountry',
			'alerts'             => array(
				'enabled'          => true,
				'recipients'       => array(),
				'new_admin'        => true,
				'plugin_changes'   => true,
				'plugin_updates'   => false,
				'firewall_changes' => true,
			),
			'traffic'            => array(
				'enabled'         => false,
				'retention_days'  => 7,
				'skip_admins'     => false,
				'skip_background' => true,
			),
			'rules'              => array(
				'ip_blocklist'     => array(
					'enabled' => true,
					'ips'     => array(),
				),
				'user_agent'       => array(
					'enabled'     => true,
					'block_empty' => true,
					'patterns'    => UserAgentRule::DEFAULT_PATTERNS,
				),
				'country'          => array(
					'enabled'       => false,
					'mode'          => 'block',
					'countries'     => array(),
					'block_unknown' => false,
					'scope'         => 'site',
				),
				'xmlrpc'           => array(
					'enabled' => true,
					'mode'    => 'block_all',
				),
				'login_lockout'    => array(
					'enabled'          => true,
					'max_attempts'     => 5,
					'window_minutes'   => 15,
					'lockout_minutes'  => 60,
					'banned_usernames' => array( 'admin', 'administrator', 'root', 'test' ),
					'generic_errors'   => true,
				),
				'rate_limit'       => array(
					'enabled'        => false,
					'max_requests'   => 240,
					'window_seconds' => 60,
					'ban_minutes'    => 10,
				),
				'waf'              => array(
					'enabled'         => true,
					'sqli'            => true,
					'xss'             => true,
					'traversal'       => true,
					'code_injection'  => true,
					'inspect_json'    => true,
					'excluded_params' => array(),
				),
				'user_enumeration' => array(
					'enabled'           => true,
					'block_author_scan' => true,
					'block_rest_users'  => true,
				),
				'sensitive_files'  => array(
					'enabled'     => true,
					'ban_minutes' => 60,
					'extra_paths' => array(),
				),
				'not_found'        => array(
					'enabled'         => true,
					'max_404'         => 20,
					'window_seconds'  => 60,
					'ban_minutes'     => 60,
					'ignore_crawlers' => true,
				),
				'uploads_php'      => array(
					'enabled'       => true,
					'htaccess'      => true,
					'check_uploads' => true,
				),
			),
		);
	}

	/**
	 * Fill in any missing keys from the defaults (two levels deep).
	 *
	 * @param array<string, mixed> $stored Stored values.
	 * @return array<string, mixed>
	 */
	private static function merge_defaults( array $stored ): array {
		$defaults = self::defaults();
		$merged   = array_merge( $defaults, array_intersect_key( $stored, $defaults ) );

		$alerts            = is_array( $stored['alerts'] ?? null ) ? $stored['alerts'] : array();
		$merged['alerts']  = array_merge( $defaults['alerts'], array_intersect_key( $alerts, $defaults['alerts'] ) );
		$traffic           = is_array( $stored['traffic'] ?? null ) ? $stored['traffic'] : array();
		$merged['traffic'] = array_merge( $defaults['traffic'], array_intersect_key( $traffic, $defaults['traffic'] ) );

		$merged['rules'] = array();
		$stored_rules    = is_array( $stored['rules'] ?? null ) ? $stored['rules'] : array();
		foreach ( $defaults['rules'] as $id => $rule_defaults ) {
			$rule                   = is_array( $stored_rules[ $id ] ?? null ) ? $stored_rules[ $id ] : array();
			$merged['rules'][ $id ] = array_merge( $rule_defaults, array_intersect_key( $rule, $rule_defaults ) );
		}
		// Automatic bans and lockouts last at most 24 hours; values stored by an older version are clamped.
		foreach ( array(
			'login_lockout'   => 'lockout_minutes',
			'sensitive_files' => 'ban_minutes',
			'not_found'       => 'ban_minutes',
			'rate_limit'      => 'ban_minutes',
		) as $id => $key ) {
			if ( isset( $merged['rules'][ $id ][ $key ] ) ) {
				$merged['rules'][ $id ][ $key ] = min( self::MAX_BAN_MINUTES, (int) $merged['rules'][ $id ][ $key ] );
			}
		}
		return $merged;
	}

	/**
	 * Read a top-level setting.
	 *
	 * @param string $key Key.
	 * @return mixed
	 */
	public function get( string $key ) {
		return $this->values[ $key ] ?? null;
	}

	/**
	 * Settings for one rule.
	 *
	 * @param string $id Rule id.
	 * @return array<string, mixed>
	 */
	public function rule( string $id ): array {
		return $this->values['rules'][ $id ] ?? array( 'enabled' => false );
	}

	/** Is the plugin in monitor (log-only) mode? */
	public function is_monitor_mode(): bool {
		return self::MODE_MONITOR === $this->values['mode'];
	}

	/**
	 * Get the full settings array.
	 *
	 * @return array<string, mixed> Full settings array.
	 */
	public function to_array(): array {
		return $this->values;
	}

	/**
	 * Merge one admin tab's submitted fields into the current settings, then sanitise.
	 *
	 * Fields the tab owns but that weren't submitted (unticked checkboxes,
	 * empty multi-selects) are treated as empty/false.
	 *
	 * @param array<string, mixed> $current Current full settings.
	 * @param array<string, mixed> $input   Submitted $_POST['wp_bouncer'] (unslashed).
	 * @param string               $tab     Tab key from TAB_FIELDS.
	 * @return array<string, mixed> Sanitised full settings.
	 */
	public static function apply_form( array $current, array $input, string $tab ): array {
		$fields = self::TAB_FIELDS[ $tab ] ?? array();
		foreach ( $fields as $field ) {
			if ( 0 === strpos( $field, 'rules.' ) ) {
				$id                      = substr( $field, 6 );
				$current['rules'][ $id ] = is_array( $input['rules'][ $id ] ?? null ) ? $input['rules'][ $id ] : array();
			} else {
				$current[ $field ] = $input[ $field ] ?? '';
			}
		}
		return self::sanitize( $current );
	}

	/**
	 * Sanitise a full settings array. Unknown keys are dropped and every value
	 * is coerced to its expected type and range.
	 *
	 * @param array<string, mixed> $in Raw settings.
	 * @return array<string, mixed>
	 */
	public static function sanitize( array $in ): array {
		$d   = self::defaults();
		$out = array();

		$out['mode']               = self::choice( $in['mode'] ?? null, array( self::MODE_ENFORCE, self::MODE_MONITOR ), $d['mode'] );
		$out['ip_source']          = self::choice( $in['ip_source'] ?? null, array_keys( IpResolver::SOURCES ), $d['ip_source'] );
		$out['trusted_proxies']    = IpUtils::without_broad( self::ip_list( $in['trusted_proxies'] ?? array() ) );
		$out['allowlist']          = IpUtils::without_broad( self::ip_list( $in['allowlist'] ?? array() ) );
		$out['log_retention_days'] = self::int_range( $in['log_retention_days'] ?? null, 1, 365, $d['log_retention_days'] );
		$out['block_message']      = self::text( $in['block_message'] ?? '', 500, $d['block_message'] );
		$out['geo_source']         = self::choice( $in['geo_source'] ?? null, array( 'database', 'header' ), $d['geo_source'] );
		$geo_header                = trim( (string) ( $in['geo_header'] ?? '' ) );
		$out['geo_header']         = preg_match( '/^[A-Za-z0-9_-]{1,64}$/', $geo_header ) ? $geo_header : $d['geo_header'];

		$alerts        = is_array( $in['alerts'] ?? null ) ? $in['alerts'] : array();
		$out['alerts'] = array(
			'enabled'          => self::bool( $alerts['enabled'] ?? false ),
			'recipients'       => self::emails( $alerts['recipients'] ?? array() ),
			'new_admin'        => self::bool( $alerts['new_admin'] ?? false ),
			'plugin_changes'   => self::bool( $alerts['plugin_changes'] ?? false ),
			'plugin_updates'   => self::bool( $alerts['plugin_updates'] ?? false ),
			'firewall_changes' => self::bool( $alerts['firewall_changes'] ?? false ),
		);

		$traffic        = is_array( $in['traffic'] ?? null ) ? $in['traffic'] : array();
		$out['traffic'] = array(
			'enabled'         => self::bool( $traffic['enabled'] ?? false ),
			'retention_days'  => self::int_range( $traffic['retention_days'] ?? null, 1, 7, $d['traffic']['retention_days'] ),
			'skip_admins'     => self::bool( $traffic['skip_admins'] ?? false ),
			'skip_background' => self::bool( $traffic['skip_background'] ?? false ),
		);

		$rules = is_array( $in['rules'] ?? null ) ? $in['rules'] : array();
		$r     = static function ( string $id ) use ( $rules ): array {
			return is_array( $rules[ $id ] ?? null ) ? $rules[ $id ] : array();
		};
		$dr    = $d['rules'];

		$rule                         = $r( 'ip_blocklist' );
		$out['rules']['ip_blocklist'] = array(
			'enabled' => self::bool( $rule['enabled'] ?? false ),
			'ips'     => self::ip_list( $rule['ips'] ?? array() ),
		);

		$rule                       = $r( 'user_agent' );
		$out['rules']['user_agent'] = array(
			'enabled'     => self::bool( $rule['enabled'] ?? false ),
			'block_empty' => self::bool( $rule['block_empty'] ?? false ),
			'patterns'    => self::ua_patterns( $rule['patterns'] ?? array() ),
		);

		$rule                    = $r( 'country' );
		$countries               = array_values(
			array_unique(
				array_filter(
					array_map( 'strtoupper', array_map( 'strval', self::lines( $rule['countries'] ?? array(), true ) ) ),
					array( Countries::class, 'is_valid' )
				)
			)
		);
		$out['rules']['country'] = array(
			'enabled'       => self::bool( $rule['enabled'] ?? false ),
			'mode'          => self::choice( $rule['mode'] ?? null, array( 'block', 'allow' ), $dr['country']['mode'] ),
			'countries'     => $countries,
			'block_unknown' => self::bool( $rule['block_unknown'] ?? false ),
			'scope'         => self::choice( $rule['scope'] ?? null, array( 'site', 'login' ), $dr['country']['scope'] ),
		);

		$rule                   = $r( 'xmlrpc' );
		$out['rules']['xmlrpc'] = array(
			'enabled' => self::bool( $rule['enabled'] ?? false ),
			'mode'    => self::choice( $rule['mode'] ?? null, array( 'block_all', 'block_abuse' ), $dr['xmlrpc']['mode'] ),
		);

		$rule                          = $r( 'login_lockout' );
		$dl                            = $dr['login_lockout'];
		$out['rules']['login_lockout'] = array(
			'enabled'          => self::bool( $rule['enabled'] ?? false ),
			'max_attempts'     => self::int_range( $rule['max_attempts'] ?? null, 1, 100, $dl['max_attempts'] ),
			'window_minutes'   => self::int_range( $rule['window_minutes'] ?? null, 1, 1440, $dl['window_minutes'] ),
			'lockout_minutes'  => self::int_range( $rule['lockout_minutes'] ?? null, 1, self::MAX_BAN_MINUTES, $dl['lockout_minutes'] ),
			'banned_usernames' => array_values(
				array_unique(
					array_filter(
						array_map(
							static function ( $u ) {
								return strtolower( substr( trim( (string) $u ), 0, 60 ) );
							},
							self::lines( $rule['banned_usernames'] ?? array(), true )
						)
					)
				)
			),
			'generic_errors'   => self::bool( $rule['generic_errors'] ?? false ),
		);

		$rule                       = $r( 'rate_limit' );
		$dl                         = $dr['rate_limit'];
		$out['rules']['rate_limit'] = array(
			'enabled'        => self::bool( $rule['enabled'] ?? false ),
			'max_requests'   => self::int_range( $rule['max_requests'] ?? null, 10, 100000, $dl['max_requests'] ),
			'window_seconds' => self::int_range( $rule['window_seconds'] ?? null, 1, 3600, $dl['window_seconds'] ),
			'ban_minutes'    => self::int_range( $rule['ban_minutes'] ?? null, 1, self::MAX_BAN_MINUTES, $dl['ban_minutes'] ),
		);

		$rule                = $r( 'waf' );
		$out['rules']['waf'] = array(
			'enabled'         => self::bool( $rule['enabled'] ?? false ),
			'sqli'            => self::bool( $rule['sqli'] ?? false ),
			'xss'             => self::bool( $rule['xss'] ?? false ),
			'traversal'       => self::bool( $rule['traversal'] ?? false ),
			'code_injection'  => self::bool( $rule['code_injection'] ?? false ),
			'inspect_json'    => self::bool( $rule['inspect_json'] ?? false ),
			'excluded_params' => array_values(
				array_unique(
					array_filter(
						self::lines( $rule['excluded_params'] ?? array(), true ),
						static function ( $p ) {
							return (bool) preg_match( '/^[A-Za-z0-9_\-]{1,100}$/', $p );
						}
					)
				)
			),
		);

		$rule                             = $r( 'user_enumeration' );
		$out['rules']['user_enumeration'] = array(
			'enabled'           => self::bool( $rule['enabled'] ?? false ),
			'block_author_scan' => self::bool( $rule['block_author_scan'] ?? false ),
			'block_rest_users'  => self::bool( $rule['block_rest_users'] ?? false ),
		);

		$rule                            = $r( 'sensitive_files' );
		$out['rules']['sensitive_files'] = array(
			'enabled'     => self::bool( $rule['enabled'] ?? false ),
			'ban_minutes' => self::int_range( $rule['ban_minutes'] ?? null, 0, self::MAX_BAN_MINUTES, $dr['sensitive_files']['ban_minutes'] ),
			'extra_paths' => array_values(
				array_unique(
					array_filter(
						array_map(
							static function ( $p ) {
								return strtolower( substr( $p, 0, 200 ) );
							},
							self::lines( $rule['extra_paths'] ?? array() )
						),
						static function ( $p ) {
							// A path fragment: at least two characters besides slashes, no spaces.
							return strlen( trim( $p, '/' ) ) >= 2 && ! preg_match( '/\s/', $p );
						}
					)
				)
			),
		);

		$rule                      = $r( 'not_found' );
		$dl                        = $dr['not_found'];
		$out['rules']['not_found'] = array(
			'enabled'         => self::bool( $rule['enabled'] ?? false ),
			'max_404'         => self::int_range( $rule['max_404'] ?? null, 3, 10000, $dl['max_404'] ),
			'window_seconds'  => self::int_range( $rule['window_seconds'] ?? null, 10, 3600, $dl['window_seconds'] ),
			'ban_minutes'     => self::int_range( $rule['ban_minutes'] ?? null, 1, self::MAX_BAN_MINUTES, $dl['ban_minutes'] ),
			'ignore_crawlers' => self::bool( $rule['ignore_crawlers'] ?? false ),
		);

		$rule                        = $r( 'uploads_php' );
		$out['rules']['uploads_php'] = array(
			'enabled'       => self::bool( $rule['enabled'] ?? false ),
			'htaccess'      => self::bool( $rule['htaccess'] ?? false ),
			'check_uploads' => self::bool( $rule['check_uploads'] ?? false ),
		);

		return $out;
	}

	/*
	 * ------------------------------------------------------------------
	 * Coercion helpers
	 * ----------------------------------------------------------------
	 */

	/**
	 * Checkbox-style boolean.
	 *
	 * @param mixed $v Value.
	 */
	private static function bool( $v ): bool {
		if ( is_string( $v ) ) {
			return ! in_array( strtolower( trim( $v ) ), array( '', '0', 'false', 'off', 'no' ), true );
		}
		return (bool) $v;
	}

	/**
	 * Restrict to an allowed set.
	 *
	 * @param mixed    $v        Value.
	 * @param string[] $allowed  Allowed values.
	 * @param string   $fallback Fallback.
	 */
	private static function choice( $v, array $allowed, string $fallback ): string {
		return is_string( $v ) && in_array( $v, $allowed, true ) ? $v : $fallback;
	}

	/**
	 * Clamp an integer, falling back if not numeric.
	 *
	 * @param mixed $v        Value.
	 * @param int   $min      Minimum.
	 * @param int   $max      Maximum.
	 * @param int   $fallback Fallback.
	 */
	private static function int_range( $v, int $min, int $max, int $fallback ): int {
		if ( ! is_numeric( $v ) ) {
			return $fallback;
		}
		return max( $min, min( $max, (int) $v ) );
	}

	/**
	 * Plain text: tags stripped, length capped.
	 *
	 * @param mixed  $v        Value.
	 * @param int    $max      Max length.
	 * @param string $fallback Used when the result is empty.
	 */
	private static function text( $v, int $max, string $fallback ): string {
		$v = trim( preg_replace( '/\s+/', ' ', strip_tags( (string) $v ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags -- wp_strip_all_tags() also removes script/style bodies and would change stored values; this class also runs in unit tests without WordPress.
		$v = function_exists( 'mb_substr' ) ? mb_substr( $v, 0, $max ) : substr( $v, 0, $max );
		return '' === $v ? $fallback : $v;
	}

	/**
	 * Split a textarea (or accept an array) into trimmed, non-empty lines.
	 *
	 * @param mixed $v            String or array.
	 * @param bool  $split_commas Also split on commas and spaces.
	 * @return string[]
	 */
	public static function lines( $v, bool $split_commas = false ): array {
		if ( is_array( $v ) ) {
			$items = array_map(
				static function ( $i ) {
					return is_scalar( $i ) ? (string) $i : '';
				},
				$v
			);
		} else {
			$items = preg_split( $split_commas ? '/[\r\n,\s]+/' : '/\r\n|\r|\n/', (string) $v );
		}
		return array_values(
			array_filter(
				array_map( 'trim', (array) $items ),
				static function ( string $item ): bool {
					return '' !== $item;
				}
			)
		);
	}

	/**
	 * Valid, de-duplicated email addresses (at most 10).
	 *
	 * @param mixed $v Textarea or array.
	 * @return string[]
	 */
	private static function emails( $v ): array {
		$out = array();
		foreach ( self::lines( $v, true ) as $email ) {
			$email = strtolower( $email );
			if ( strlen( $email ) <= 254 && false !== filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
				$out[] = $email;
			}
		}
		return array_slice( array_values( array_unique( $out ) ), 0, 10 );
	}

	/**
	 * Over-broad entries (see IpUtils::is_broad_range()) that sanitize() would
	 * drop from the trusted proxies and the allowlist.
	 *
	 * @param array<string, mixed> $in Raw or merged settings.
	 * @return string[] The entries, de-duplicated, in the order found.
	 */
	public static function dropped_broad_ranges( array $in ): array {
		$dropped = array();
		foreach ( array( 'trusted_proxies', 'allowlist' ) as $key ) {
			foreach ( self::ip_list( $in[ $key ] ?? array() ) as $entry ) {
				if ( IpUtils::is_broad_range( $entry ) ) {
					$dropped[] = $entry;
				}
			}
		}
		return array_values( array_unique( $dropped ) );
	}

	/**
	 * Valid, de-duplicated IP / CIDR entries.
	 *
	 * @param mixed $v Textarea or array.
	 * @return string[]
	 */
	private static function ip_list( $v ): array {
		return array_values( array_unique( array_filter( self::lines( $v, true ), array( IpUtils::class, 'is_valid_range' ) ) ) );
	}

	/**
	 * User-Agent patterns; regex entries that don't compile are dropped.
	 *
	 * @param mixed $v Textarea or array.
	 * @return string[]
	 */
	private static function ua_patterns( $v ): array {
		$out = array();
		foreach ( self::lines( $v ) as $pattern ) {
			$pattern = substr( $pattern, 0, 200 );
			if ( UserAgentRule::is_regex( $pattern ) && false === @preg_match( $pattern, '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors -- validating a user-entered regex: an invalid pattern emits a warning and returns false, which is exactly what is tested.
				continue;
			}
			$out[] = $pattern;
		}
		return array_slice( array_values( array_unique( $out ) ), 0, UserAgentRule::MAX_PATTERNS );
	}

	/**
	 * Keep the server-wide parts of the settings from changing when the user
	 * lacks wpb_manage_firewall: the uploads rule's on/off and .htaccess switches are taken from
	 * $old, and regex User-Agent patterns that are not already in $old are
	 * dropped (removing existing ones stays allowed).
	 *
	 * @param array<string, mixed> $old Stored settings.
	 * @param array<string, mixed> $updated Settings about to be stored.
	 * @return array<string, mixed>
	 */
	public static function preserve_privileged( array $old, array $updated ): array {
		// The whole uploads rule is pinned: wants_htaccess() is "enabled and htaccess", so turning the rule off would also remove the block.
		foreach ( array( 'enabled', 'htaccess' ) as $key ) {
			if ( isset( $old['rules']['uploads_php'][ $key ] ) && isset( $updated['rules']['uploads_php'] ) ) {
				$updated['rules']['uploads_php'][ $key ] = $old['rules']['uploads_php'][ $key ];
			}
		}
		if ( isset( $updated['rules']['user_agent']['patterns'] ) && is_array( $updated['rules']['user_agent']['patterns'] ) ) {
			$known = (array) ( $old['rules']['user_agent']['patterns'] ?? array() );
			$keep  = array();
			foreach ( $updated['rules']['user_agent']['patterns'] as $pattern ) {
				if ( UserAgentRule::is_regex( (string) $pattern ) && ! in_array( $pattern, $known, true ) ) {
					continue;
				}
				$keep[] = $pattern;
			}
			$updated['rules']['user_agent']['patterns'] = $keep;
		}
		return $updated;
	}
}
