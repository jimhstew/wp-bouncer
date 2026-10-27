<?php
/**
 * Turns security events into an alert email.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Alerts;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP: no WordPress calls, so the wording is unit-tested.
 *
 * An event is array{type: string, title: string, detail: string}. type is
 * 'admin' (a new or promoted administrator), 'plugin' (a plugin change) or
 * 'firewall' (a change to the firewall's own settings, or the emergency switch) or
 * 'login' (an administrator logged in from a new location).
 */
final class AlertFormatter {

	/**
	 * Build the email.
	 *
	 * @param array<int, array{type: string, title: string, detail: string}> $events  What happened.
	 * @param array<string, string>                                          $context site_name, site_url, time, actor, ip, country, user_agent, settings_url.
	 * @return array{subject: string, body: string}
	 */
	public static function format( array $events, array $context ): array {
		$site = self::clean( $context['site_name'] ?? '' );
		if ( '' === $site ) {
			$site = self::clean( $context['site_url'] ?? 'WordPress' );
		}

		if ( 1 === count( $events ) ) {
			$subject = sprintf( '[%s] WP Bouncer alert: %s', $site, self::clean( $events[0]['title'] ) );
		} else {
			$admins   = count(
				array_filter(
					$events,
					static function ( $e ) {
						return 'admin' === $e['type'];
					}
				)
			);
			$firewall = count(
				array_filter(
					$events,
					static function ( $e ) {
						return 'firewall' === $e['type'];
					}
				)
			);
			$logins   = count(
				array_filter(
					$events,
					static function ( $e ) {
						return 'login' === $e['type'];
					}
				)
			);
			$extra    = '';
			if ( $admins > 0 ) {
				$extra = ' including a new administrator';
			} elseif ( $logins > 0 ) {
				$extra = ' including an administrator login from a new location';
			} elseif ( $firewall > 0 ) {
				$extra = ' including firewall changes';
			}
			$subject = sprintf(
				'[%s] WP Bouncer alert: %d security events%s',
				$site,
				count( $events ),
				$extra
			);
		}

		$lines   = array();
		$lines[] = 'WP Bouncer noticed ' . ( 1 === count( $events ) ? 'a change' : 'these changes' ) . ' on ' . self::clean( $context['site_url'] ?? $site ) . ':';
		$lines[] = '';
		foreach ( $events as $event ) {
			$lines[] = '* ' . self::clean( $event['title'] );
			if ( '' !== trim( $event['detail'] ) ) {
				$lines[] = '  ' . self::clean( $event['detail'] );
			}
		}
		$lines[] = '';
		$lines[] = 'When:       ' . self::clean( $context['time'] ?? '' );
		$lines[] = 'Done by:    ' . self::clean( $context['actor'] ?? '' );
		$where   = self::clean( $context['ip'] ?? '' );
		if ( '' !== ( $context['country'] ?? '' ) ) {
			$where .= ' (' . self::clean( $context['country'] ) . ')';
		}
		$lines[] = 'From IP:    ' . ( '' !== $where ? $where : 'unknown' );
		if ( '' !== ( $context['user_agent'] ?? '' ) ) {
			$lines[] = 'Browser:    ' . self::clean( $context['user_agent'] );
		}
		$lines[]     = '';
		$only_logins = count(
			array_filter(
				$events,
				static function ( $e ) {
					return 'login' === $e['type'];
				}
			)
		) === count( $events );
		if ( $only_logins ) {
			$lines[] = 'If this was you, there is nothing to do. If not, change this account\'s password, revoke its application passwords and log out its other sessions (Users → Profile), then check the Activity Log.';
		} else {
			$lines[] = 'If you made ' . ( 1 === count( $events ) ? 'this change' : 'these changes' ) . ', there is nothing to do.';
			$lines[] = 'If not, someone else may have access to your site. Log in, check';
			$lines[] = 'Users and Plugins, change your passwords, and look at the WP Bouncer';
			$lines[] = 'Activity Log for this IP.';
		}
		if ( '' !== ( $context['settings_url'] ?? '' ) ) {
			$lines[] = '';
			$lines[] = 'Alert settings: ' . self::clean( $context['settings_url'] );
		}

		return array(
			'subject' => $subject,
			'body'    => implode( "\n", $lines ) . "\n",
		);
	}

	/**
	 * One line of plain text: no control characters (no header injection
	 * through a username), length capped.
	 *
	 * @param string $text Text.
	 */
	public static function clean( string $text ): string {
		$text = (string) preg_replace( '/[\x00-\x1F\x7F]+/', ' ', $text );
		$text = trim( $text );
		return strlen( $text ) > 300 ? substr( $text, 0, 297 ) . '...' : $text;
	}

	/**
	 * Merge duplicates. Creating an administrator fires both "user registered"
	 * and "role set" hooks; only one line should appear.
	 *
	 * @param array<int, array{type: string, title: string, detail: string, key?: string, log_detail?: string, critical?: bool, logged?: bool, recipients?: string[], settings?: bool, uncapped?: bool, blog?: int, capped?: bool, ctx?: array<string, string>}> $events Events.
	 * @return array<int, array{type: string, title: string, detail: string, log_detail?: string, critical?: bool, logged?: bool, recipients?: string[], settings?: bool, uncapped?: bool, blog?: int, capped?: bool, ctx?: array<string, string>}>
	 */
	public static function dedupe( array $events ): array {
		$out = array();
		foreach ( $events as $event ) {
			$key = $event['key'] ?? ( $event['type'] . '|' . $event['title'] . '|' . $event['detail'] . '|' . ( $event['blog'] ?? '' ) );
			if ( ! isset( $out[ $key ] ) ) {
				$out[ $key ] = array(
					'type'   => $event['type'],
					'title'  => $event['title'],
					'detail' => $event['detail'],
				);
				if ( isset( $event['log_detail'] ) ) {
					$out[ $key ]['log_detail'] = $event['log_detail'];
				}
			}
			if ( ! empty( $event['critical'] ) ) {
				$out[ $key ]['critical'] = true;
			}
			foreach ( array( 'settings', 'uncapped', 'blog', 'ctx' ) as $extra ) {
				if ( isset( $event[ $extra ] ) && ! isset( $out[ $key ][ $extra ] ) ) {
					$out[ $key ][ $extra ] = $event[ $extra ];
				}
			}
			if ( ! empty( $event['recipients'] ) ) {
				$out[ $key ]['recipients'] = array_values( array_unique( array_merge( $out[ $key ]['recipients'] ?? array(), $event['recipients'] ) ) );
			}
			if ( ! empty( $event['logged'] ) ) {
				$out[ $key ]['logged'] = true;
			}
			if ( ! empty( $event['capped'] ) ) {
				$out[ $key ]['capped'] = true;
			}
		}
		return array_values( $out );
	}
}
