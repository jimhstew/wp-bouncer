<?php
/**
 * Fixed admin redirect messages.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Maps message codes (carried in the `wpb_msg` query argument) to translated text.
 *
 * Handlers redirect with a code plus validated arguments; nothing from the
 * query string is ever shown as free text, so a crafted link cannot make the
 * admin screen display attacker-chosen wording. Details that are not
 * representable as a validated argument (an error returned by the mail system or
 * a download) travel in a short-lived per-user flash value on the server.
 */
final class MessageCodes {

	/** Query argument carrying the code. */
	public const QUERY_KEY = 'wpb_msg';

	/** Prefix of query arguments carrying message arguments. */
	public const ARG_PREFIX = 'wpb_';

	/** Message arguments that may travel in the URL. */
	private const URL_ARGS = array( 'ip', 'n', 'skipped', 'result', 'rule', 'state', 'allow', 'dropped', 'noproxy', 'upload' );

	/** Codes that exist. Texts are built in text() so they can be translated. */
	public const CODES = array(
		'saved',
		'unknown_section',
		'unknown_rule',
		'managed_by_network',
		'rule_toggled',
		'shared_refusal',
		'remote_addr_set',
		'proxy_trusted',
		'unknown_header',
		'proxy_unknown',
		'proxy_public',
		'peer_changed',
		'unknown_action',
		'ip_invalid',
		'ip_own',
		'ip_blocked',
		'ip_unlocked',
		'ip_unlock_invalid',
		'log_cleared',
		'traffic_cleared',
		'test_failed',
		'test_sent',
		'probe_result',
		'uploads_sync_failed',
		'uploads_synced',
		'geo_upload_error',
		'geo_bad_type',
		'geo_no_arrive',
		'geo_bad_url',
		'geo_download_failed',
		'geo_choose',
		'geo_error',
		'geo_done',
		'geo_cancelled',
	);

	/** Codes whose text uses the server-side flash detail. */
	private const DETAIL_CODES = array( 'saved', 'rule_toggled', 'shared_refusal', 'remote_addr_set', 'proxy_trusted', 'test_failed', 'test_sent', 'geo_download_failed', 'geo_error' );

	/**
	 * Does this code read the flash detail? Only those may consume it.
	 *
	 * @param string $code Message code.
	 */
	public static function uses_detail( string $code ): bool {
		return in_array( $code, self::DETAIL_CODES, true );
	}

	/**
	 * Text for a code, or null for an unknown code (nothing is shown then).
	 *
	 * @param string               $code Message code.
	 * @param array<string, mixed> $args Arguments. Each is validated here; an invalid one is treated as absent.
	 * @return string|null Plain text (escape on output). Every entry of CODES has a case above; MessageCodesTest checks that.
	 */
	public static function text( string $code, array $args = array() ): ?string {
		if ( ! in_array( $code, self::CODES, true ) ) {
			return null;
		}
		$ip      = self::ip_arg( $args, 'ip' );
		$detail  = isset( $args['detail'] ) ? sanitize_text_field( (string) $args['detail'] ) : '';
		$allowed = self::allow_note( self::ip_arg( $args, 'allow' ), $detail );

		switch ( $code ) {
			case 'saved':
				$message = __( 'Settings saved.', 'wp-bouncer' );
				$dropped = self::ranges_arg( $args, 'dropped' );
				if ( array() !== $dropped ) {
					$message .= ' ' . sprintf(
						/* translators: %s: list of IP ranges. */
						__( 'These entries were removed because they are too broad to be safe: %s.', 'wp-bouncer' ),
						implode( ', ', $dropped )
					);
				}
				if ( ! empty( $args['noproxy'] ) ) {
					$message .= ' ' . __( 'Warning: an IP header is selected but no trusted proxies are listed, so the header is ignored and IP bans and lockouts are suspended (login attempts are logged; rate limiting is effectively off) until you add your proxy.', 'wp-bouncer' );
				}
				return $message . $allowed;
			case 'unknown_section':
				return __( 'Unknown settings section.', 'wp-bouncer' );
			case 'managed_by_network':
				return __( 'That setting is managed by your network administrator.', 'wp-bouncer' );
			case 'unknown_rule':
				return __( 'Unknown rule.', 'wp-bouncer' );
			case 'rule_toggled':
				$rule = isset( $args['rule'] ) ? (string) $args['rule'] : '';
				if ( ! isset( AdminController::rule_labels()[ $rule ] ) ) {
					return null;
				}
				return sprintf(
					/* translators: 1: rule name, 2: "enabled" or "disabled". */
					__( '%1$s %2$s.', 'wp-bouncer' ),
					AdminController::rule_title( $rule ),
					'on' === ( $args['state'] ?? '' ) ? __( 'enabled', 'wp-bouncer' ) : __( 'disabled', 'wp-bouncer' )
				) . $allowed;
			case 'shared_refusal':
				$why = '' !== $detail ? ' (' . $detail . ')' : '';
				return sprintf(
					/* translators: %s: reason in brackets, or empty. */
					__( 'These settings would block you%s, but your address cannot be told apart from a shared proxy, so it cannot safely be allowlisted. Nothing was saved. Fix the IP setup notice at the top of the page first.', 'wp-bouncer' ),
					$why
				);
			case 'remote_addr_set':
				return __( 'WP Bouncer now uses the connection address as the visitor IP.', 'wp-bouncer' ) . $allowed;
			case 'proxy_trusted':
				if ( '' === $ip ) {
					return null;
				}
				return sprintf(
					/* translators: %s: IP address. */
					__( '%s is now a trusted proxy.', 'wp-bouncer' ),
					$ip
				) . $allowed;
			case 'unknown_header':
				return __( 'Unknown IP header.', 'wp-bouncer' );
			case 'proxy_unknown':
				return __( 'Could not work out which proxy to trust. Set the IP header and trusted proxies under General.', 'wp-bouncer' );
			case 'proxy_public':
				return __( 'The connection address is a public one, so it looks like a CDN or public proxy. List its full published IP ranges under Trusted proxies instead.', 'wp-bouncer' );
			case 'peer_changed':
				return __( 'The connection address changed since the notice was shown, so nothing was trusted. Reload the page and try again.', 'wp-bouncer' );
			case 'unknown_action':
				return __( 'Unknown action.', 'wp-bouncer' );
			case 'ip_invalid':
				return __( 'That is not a valid IP address.', 'wp-bouncer' );
			case 'ip_own':
				return __( 'Refusing to block your own IP address.', 'wp-bouncer' );
			case 'ip_blocked':
				if ( '' === $ip ) {
					return null;
				}
				/* translators: %s: IP address. */
				return sprintf( __( '%s added to the IP blocklist.', 'wp-bouncer' ), $ip );
			case 'ip_unlock_invalid':
				return __( 'That is not a valid IP address.', 'wp-bouncer' );
			case 'ip_unlocked':
				if ( '' === $ip ) {
					return null;
				}
				/* translators: %s: IP address. */
				return sprintf( __( 'Lockouts and bans cleared for %s.', 'wp-bouncer' ), $ip );
			case 'log_cleared':
				return __( 'Activity log cleared.', 'wp-bouncer' );
			case 'traffic_cleared':
				return __( 'Traffic log cleared.', 'wp-bouncer' );
			case 'test_failed':
				if ( '' === $detail ) {
					return null;
				}
				/* translators: %s: error message. */
				return sprintf( __( 'The test email was not sent: %s', 'wp-bouncer' ), $detail );
			case 'test_sent':
				if ( '' === $detail ) {
					return null;
				}
				/* translators: %s: email addresses. */
				return sprintf( __( 'Test email sent to %s. If it does not arrive, check spam, then your site\'s mail setup.', 'wp-bouncer' ), $detail );
			case 'probe_result':
				$result = isset( $args['result'] ) ? (string) $args['result'] : '';
				return in_array( $result, array( 'protected', 'unprotected', 'broken', 'unknown' ), true ) ? AdminController::probe_message( $result ) : null;
			case 'uploads_sync_failed':
				return __( 'Could not update wp-content/uploads/.htaccess. Check that the folder is writable, or add the rule to your server config by hand.', 'wp-bouncer' );
			case 'uploads_synced':
				return 'removed' === ( $args['state'] ?? '' )
					? __( 'The block was removed from wp-content/uploads/.htaccess.', 'wp-bouncer' )
					: __( 'The block is in wp-content/uploads/.htaccess.', 'wp-bouncer' );
			case 'geo_upload_error':
				return AdminController::upload_error_message( isset( $args['upload'] ) ? (int) $args['upload'] : 0 );
			case 'geo_bad_type':
				return __( 'Please upload a .csv or .csv.gz file.', 'wp-bouncer' );
			case 'geo_no_arrive':
				return __( 'The upload did not arrive. Try again, or import by URL.', 'wp-bouncer' );
			case 'geo_bad_url':
				return __( 'That URL is not valid.', 'wp-bouncer' );
			case 'geo_download_failed':
				if ( '' === $detail ) {
					return null;
				}
				/* translators: %s: error message. */
				return sprintf( __( 'Download failed: %s', 'wp-bouncer' ), $detail );
			case 'geo_choose':
				return __( 'Choose a file or enter a URL.', 'wp-bouncer' );
			case 'geo_error':
				return '' !== $detail ? $detail : __( 'The geo database import failed.', 'wp-bouncer' );
			case 'geo_done':
				return sprintf(
					/* translators: 1: rows imported, 2: rows skipped. */
					__( 'Geo database imported: %1$s ranges loaded, %2$s lines skipped.', 'wp-bouncer' ),
					number_format_i18n( max( 0, (int) ( $args['n'] ?? 0 ) ) ),
					number_format_i18n( max( 0, (int) ( $args['skipped'] ?? 0 ) ) )
				);
			case 'geo_cancelled':
				return __( 'Import stopped. The ranges loaded so far are in use; import again for complete data.', 'wp-bouncer' );
			default:
				return null;
		}
	}

	/**
	 * Query arguments for a redirect: the code and its URL-safe arguments.
	 *
	 * @param string               $code Message code.
	 * @param array<string, mixed> $args Message arguments ("detail" is not put in the URL).
	 * @return array<string, string>
	 */
	public static function to_query( string $code, array $args = array() ): array {
		$query = array( self::QUERY_KEY => $code );
		foreach ( self::URL_ARGS as $key ) {
			if ( isset( $args[ $key ] ) && '' !== (string) $args[ $key ] ) {
				$value = $args[ $key ];
				if ( is_array( $value ) ) {
					$value = implode( ',', $value );
				}
				$query[ self::ARG_PREFIX . $key ] = rawurlencode( (string) $value );
			}
		}
		return $query;
	}

	/**
	 * Read the code and arguments from a query array ($_GET).
	 *
	 * @param array<string, mixed> $get Query values (unslashed or not; they are sanitised).
	 * @return array{0: string, 1: array<string, string>} Code ('' if none) and raw string arguments.
	 */
	public static function from_query( array $get ): array {
		if ( ! isset( $get[ self::QUERY_KEY ] ) || ! is_string( $get[ self::QUERY_KEY ] ) ) {
			return array( '', array() );
		}
		$code = sanitize_key( $get[ self::QUERY_KEY ] );
		$args = array();
		foreach ( self::URL_ARGS as $key ) {
			$name = self::ARG_PREFIX . $key;
			if ( isset( $get[ $name ] ) && is_string( $get[ $name ] ) ) {
				$args[ $key ] = sanitize_text_field( $get[ $name ] );
			}
		}
		return array( $code, $args );
	}

	/**
	 * Keep a server-side detail for the next screen (per user, 2 minutes).
	 *
	 * @param string $detail Plain text.
	 */
	public static function flash( string $detail ): void {
		set_transient( self::flash_key(), $detail, 2 * MINUTE_IN_SECONDS );
	}

	/**
	 * Read and clear the flash detail.
	 *
	 * @return string
	 */
	public static function take_flash(): string {
		$value = get_transient( self::flash_key() );
		if ( false === $value ) {
			return '';
		}
		delete_transient( self::flash_key() );
		return is_string( $value ) ? $value : '';
	}

	/** Transient name for the current user. */
	private static function flash_key(): string {
		return 'wpb_flash_' . get_current_user_id();
	}

	/**
	 * A validated single IP address argument.
	 *
	 * @param array<string, mixed> $args Arguments.
	 * @param string               $key  Key.
	 */
	private static function ip_arg( array $args, string $key ): string {
		$value = isset( $args[ $key ] ) ? trim( (string) $args[ $key ] ) : '';
		return IpUtils::is_valid( $value ) ? $value : '';
	}

	/**
	 * A comma-separated list argument where every entry must be a valid address or range.
	 *
	 * @param array<string, mixed> $args Arguments.
	 * @param string               $key  Key.
	 * @return string[]
	 */
	private static function ranges_arg( array $args, string $key ): array {
		$raw = $args[ $key ] ?? array();
		if ( is_string( $raw ) ) {
			$raw = '' === $raw ? array() : explode( ',', $raw );
		}
		$out = array();
		foreach ( (array) $raw as $entry ) {
			$entry = trim( (string) $entry );
			if ( IpUtils::is_valid_range( $entry ) ) {
				$out[] = $entry;
			}
		}
		return $out;
	}

	/**
	 * Sentence appended when the admin's own IP was allowlisted.
	 *
	 * @param string $ip     Validated address, or ''.
	 * @param string $reason Server-originated block reason, or ''.
	 */
	private static function allow_note( string $ip, string $reason = '' ): string {
		if ( '' === $ip ) {
			return '';
		}
		return ' ' . sprintf(
			/* translators: 1: IP address, 2: reason in brackets, or empty. */
			__( 'These settings would have blocked you%2$s, so your IP %1$s was added to the allowlist.', 'wp-bouncer' ),
			$ip,
			'' !== $reason ? ' (' . $reason . ')' : ''
		);
	}
}
