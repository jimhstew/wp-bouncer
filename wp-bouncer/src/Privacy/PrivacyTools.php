<?php
/**
 * WordPress personal-data exporter, eraser and privacy-policy text.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Privacy;

use WPBouncer\AdminLogins\AdminLoginRecorder;
use WPBouncer\Alerts\AlertNotifier;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Login\LoginGuard;
use WPBouncer\Plugin;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own log tables; personal data must not be served from a cache.

/**
 * Requests are by email address, so only visitors with an account can be
 * matched. Logs hold IPs, and an IP is not proof of identity, so there is no
 * IP-based export.
 *
 * - Traffic log: exported and deleted by user_id.
 * - Block log: rows are kept (legitimate interest in site security) and only
 *   the personal tokens in `reason` are replaced with "[erased]": the login
 *   (and email) at the fixed positions where the plugin writes them. Rows that
 *   are the user's own (for example their failed logins) also lose their URL.
 *   Audit rows (rule "alerts") keep their URL, title, actor and user IDs.
 *
 * On multisite the callbacks act on the current site's tables only; run the
 * request on each site that holds data for the person.
 */
final class PrivacyTools {

	/** Group id in the export. */
	public const GROUP = 'wp-bouncer';

	/** Traffic rows per exporter/eraser page. */
	public const TRAFFIC_PAGE = 500;

	/** Width of the block-log id window scanned per eraser page. */
	public const LOG_BATCH = 1000;

	/** Longest `reason` the column holds. */
	private const REASON_MAX = 255;

	/** Value left in `reason` of an erased block-log row. */
	public const ERASED = '[erased]';

	/**
	 * Plugin.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Set up the PrivacyTools.
	 *
	 * @param Plugin $plugin Plugin.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/** Hook into the WordPress privacy tools. */
	public function register(): void {
		add_filter( 'wp_privacy_personal_data_exporters', array( $this, 'add_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( $this, 'add_erasers' ) );
		add_action( 'admin_init', array( $this, 'add_policy_text' ) );
	}

	/**
	 * Register the exporter.
	 *
	 * @param mixed $exporters Registered exporters.
	 * @return array<string, mixed>
	 */
	public function add_exporter( $exporters ): array {
		$exporters                       = is_array( $exporters ) ? $exporters : array();
		$exporters['wp-bouncer-traffic'] = array(
			'exporter_friendly_name' => __( 'Site security: traffic log', 'wp-bouncer' ),
			'callback'               => array( $this, 'export_traffic' ),
		);
		return $exporters;
	}

	/**
	 * Register the erasers.
	 *
	 * @param mixed $erasers Registered erasers.
	 * @return array<string, mixed>
	 */
	public function add_erasers( $erasers ): array {
		$erasers                       = is_array( $erasers ) ? $erasers : array();
		$erasers['wp-bouncer-traffic'] = array(
			'eraser_friendly_name' => __( 'Site security: traffic log', 'wp-bouncer' ),
			'callback'             => array( $this, 'erase_traffic' ),
		);
		$erasers['wp-bouncer-log']     = array(
			'eraser_friendly_name' => __( 'Site security: block log', 'wp-bouncer' ),
			'callback'             => array( $this, 'erase_log' ),
		);
		return $erasers;
	}

	/**
	 * Table name.
	 *
	 * @param string $name Table suffix.
	 */
	private function table( string $name ): string {
		global $wpdb;
		return $wpdb->prefix . 'bouncer_' . $name;
	}

	/**
	 * The user behind an email address, or null.
	 *
	 * @param string $email Email address.
	 */
	private function user( string $email ): ?\WP_User {
		$user = get_user_by( 'email', $email );
		return $user instanceof \WP_User ? $user : null;
	}

	/**
	 * Export a user's traffic-log rows.
	 *
	 * @param string $email Email address of the requester.
	 * @param int    $page  Page, from 1.
	 * @return array{data: array<int, array<string, mixed>>, done: bool}
	 */
	public function export_traffic( $email, $page = 1 ): array {
		global $wpdb;
		$user = $this->user( (string) $email );
		if ( null === $user ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}
		$page   = max( 1, (int) $page );
		$key    = 'wp_bouncer_export_' . md5( $user->ID . '|' . $page );
		$cursor = $page > 1 ? get_transient( $key ) : 0;
		$table  = $this->table( 'traffic' );
		$cols   = 'id, created_at, ip, method, uri, referrer, user_agent, status';
		if ( false !== $cursor ) {
			// Keyset paging: continue after the last id of the previous page.
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT {$cols} FROM {$table} WHERE user_id = %d AND id > %d ORDER BY id LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- the table name is built from $wpdb->prefix; values are bound.
					$user->ID,
					(int) $cursor,
					self::TRAFFIC_PAGE
				),
				ARRAY_A
			);
		} else {
			// Page asked for out of order (or the cursor expired): fall back to an offset.
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT {$cols} FROM {$table} WHERE user_id = %d ORDER BY id LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- the table name is built from $wpdb->prefix; values are bound.
					$user->ID,
					self::TRAFFIC_PAGE,
					( $page - 1 ) * self::TRAFFIC_PAGE
				),
				ARRAY_A
			);
		}
		$rows = is_array( $rows ) ? $rows : array();

		$data = array();
		foreach ( $rows as $row ) {
			$data[] = array(
				'group_id'          => self::GROUP,
				'group_label'       => __( 'Site security: traffic log', 'wp-bouncer' ),
				'group_description' => __( 'Requests made to this site, kept briefly for troubleshooting.', 'wp-bouncer' ),
				'item_id'           => 'wp-bouncer-traffic-' . (int) $row['id'],
				'data'              => array(
					array(
						'name'  => __( 'Time (UTC)', 'wp-bouncer' ),
						'value' => (string) $row['created_at'],
					),
					array(
						'name'  => __( 'IP address', 'wp-bouncer' ),
						'value' => (string) $row['ip'],
					),
					array(
						'name'  => __( 'Request', 'wp-bouncer' ),
						'value' => trim( (string) $row['method'] . ' ' . (string) $row['uri'] ),
					),
					array(
						'name'  => __( 'Referrer', 'wp-bouncer' ),
						'value' => (string) $row['referrer'],
					),
					array(
						'name'  => __( 'Browser (User-Agent)', 'wp-bouncer' ),
						'value' => (string) $row['user_agent'],
					),
					array(
						'name'  => __( 'Response status', 'wp-bouncer' ),
						'value' => (string) $row['status'],
					),
				),
			);
		}
		$done = count( $rows ) < self::TRAFFIC_PAGE;
		if ( ! $done ) {
			set_transient( 'wp_bouncer_export_' . md5( $user->ID . '|' . ( $page + 1 ) ), (int) end( $rows )['id'], HOUR_IN_SECONDS );
		}
		return array(
			'data' => $data,
			'done' => $done,
		);
	}

	/**
	 * Delete a user's traffic-log rows, one batch per call.
	 *
	 * @param string $email Email address of the requester.
	 * @param int    $page  Page (unused: deleted rows drop out of the next select).
	 * @return array{items_removed: int, items_retained: bool, messages: string[], done: bool}
	 */
	public function erase_traffic( $email, $page = 1 ): array {
		global $wpdb;
		unset( $page );
		$result = array(
			'items_removed'  => 0,
			'items_retained' => false,
			'messages'       => array(),
			'done'           => true,
		);
		$user   = $this->user( (string) $email );
		if ( null === $user ) {
			return $result;
		}
		$ids = $wpdb->get_col(
			$wpdb->prepare(
				'SELECT id FROM ' . $this->table( 'traffic' ) . ' WHERE user_id = %d ORDER BY id LIMIT %d', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- the table name is built from $wpdb->prefix; values are bound.
				$user->ID,
				self::TRAFFIC_PAGE
			)
		);
		$ids = array_map( 'intval', is_array( $ids ) ? $ids : array() );
		if ( $ids ) {
			$wpdb->query(
				$wpdb->prepare(
					'DELETE FROM ' . $this->table( 'traffic' ) . ' WHERE id IN (' . implode( ',', array_fill( 0, count( $ids ), '%d' ) ) . ')', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- the table name is built from $wpdb->prefix; one %d per id.
					$ids
				)
			);
		}
		$result['items_removed'] = count( $ids );
		$result['done']          = count( $ids ) < self::TRAFFIC_PAGE;
		return $result;
	}

	/**
	 * Replace the user's login and email in a block-log reason, at the fixed
	 * positions where the plugin writes them, and nowhere else.
	 *
	 * Forms by rule (see LoginGuard and AlertNotifier):
	 * - login_lockout: Tried banned username "LOGIN"; (last username "LOGIN")
	 * - alerts: Username: LOGIN; , email: EMAIL; — by LOGIN (user ID N);
	 *   (request by LOGIN, user ID N)
	 *
	 * Matching is case-insensitive. Rows of any other rule, WAF parameter
	 * names, User-Agent patterns and other users' names are never touched.
	 *
	 * @param string $reason Stored reason.
	 * @param string $login  User's login.
	 * @param string $email  User's email.
	 * @param int    $id     User ID.
	 * @param string $rule   Rule id of the row.
	 * @return string|false|null The new reason, null if nothing in it was the user's, false if the text could not be processed.
	 */
	public static function redact_reason( string $reason, string $login, string $email, int $id, string $rule = AlertNotifier::LOG_RULE ) {
		$patterns = array();
		$l        = preg_quote( $login, '/' );
		if ( LoginGuard::RULE_ID === $rule && '' !== $login ) {
			$patterns[] = '/(Tried banned username ")' . $l . '(")/i';
			$patterns[] = '/(\(last username ")' . $l . '("\))/i';
		} elseif ( AlertNotifier::LOG_RULE === $rule ) {
			if ( '' !== $login ) {
				$patterns[] = '/(Username: )' . $l . '(?=,| — |$)/i';
				$patterns[] = '/( — by )' . $l . '( \(user ID ' . $id . '\))/i';
				$patterns[] = '/(\(request by )' . $l . '(, user ID ' . $id . '\))/i';
			}
			if ( '' !== $email ) {
				$patterns[] = '/(, email: )' . preg_quote( $email, '/' ) . '(?=,| — |$)/i';
			}
		}
		$out = $reason;
		foreach ( $patterns as $pattern ) {
			$replacement = '${1}' . self::ERASED . '${2}';
			$next        = preg_replace( $pattern . 'u', $replacement, $out );
			if ( null === $next ) {
				// Not valid UTF-8: match on the raw bytes instead.
				$next = preg_replace( $pattern, $replacement, $out );
			}
			if ( null === $next ) {
				return false;
			}
			$out = $next;
		}
		return $out === $reason ? null : self::fit( $out );
	}

	/**
	 * Fit a reason into the column, trimming the middle so a trailing
	 * "(user ID N)" part survives.
	 *
	 * @param string $text Reason.
	 */
	private static function fit( string $text ): string {
		if ( mb_strlen( $text ) <= self::REASON_MAX ) {
			return $text;
		}
		$tail = 1 === preg_match( '/ \((?:[^()]*, )?user ID \d+\)$/u', $text, $m ) ? $m[0] : '';
		return mb_substr( $text, 0, self::REASON_MAX - mb_strlen( $tail ) - 1 ) . '…' . $tail;
	}

	/**
	 * Redact personal tokens in block-log rows, one id window per call.
	 *
	 * Rows are kept. Only rows that carry the user's login or email at a
	 * known position change: `reason` gets "[erased]" in place of the token.
	 * `uri` is emptied only on login_lockout rows (the user's own failed
	 * logins); audit rows (rule "alerts") keep their URL, title, actor and
	 * user IDs. The scan is windowed: page N covers 1,000 ids from the low
	 * bound. Page 1 fixes the id range for the request (kept in a transient),
	 * so purges and floods meanwhile can't skip rows or postpone `done`.
	 *
	 * @param string $email Email address of the requester.
	 * @param int    $page  Page, from 1.
	 * @return array{items_removed: int, items_retained: bool, messages: string[], done: bool}
	 */
	public function erase_log( $email, $page = 1 ): array {
		global $wpdb;
		$result = array(
			'items_removed'  => 0,
			'items_retained' => false,
			'messages'       => array(),
			'done'           => true,
		);
		$user   = $this->user( (string) $email );
		if ( null === $user ) {
			return $result;
		}

		$page  = max( 1, (int) $page );
		$table = $this->table( 'log' );
		$key   = 'wp_bouncer_erase_range_' . $user->ID;
		$range = $page > 1 ? get_transient( $key ) : false;
		if ( ! is_array( $range ) || ! isset( $range[0], $range[1] ) ) {
			// Page 1, or the range expired: take the current bounds.
			$bounds = $wpdb->get_row( "SELECT MIN(id) AS lo, MAX(id) AS hi FROM {$table}", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- the table name is built from $wpdb->prefix; no values.
			$range  = array(
				is_array( $bounds ) && null !== $bounds['lo'] ? (int) $bounds['lo'] : 0,
				is_array( $bounds ) && null !== $bounds['hi'] ? (int) $bounds['hi'] : -1,
			);
			if ( 1 === $page ) {
				set_transient( $key, $range, HOUR_IN_SECONDS );
			}
		}
		$lo   = (int) $range[0];
		$hi   = (int) $range[1];
		$from = $lo + ( $page - 1 ) * self::LOG_BATCH;
		$to   = $from + self::LOG_BATCH;
		$bad  = 0;

		if ( $hi >= $from ) {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT id, rule, reason FROM {$table} WHERE id >= %d AND id < %d AND rule IN (%s, %s) AND (reason LIKE %s OR reason LIKE %s) ORDER BY id", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- the table name is built from $wpdb->prefix; values are bound.
					$from,
					$to,
					LoginGuard::RULE_ID,
					AlertNotifier::LOG_RULE,
					'%' . $wpdb->esc_like( $user->user_login ) . '%',
					'%' . $wpdb->esc_like( $user->user_email ) . '%'
				),
				ARRAY_A
			);
			foreach ( is_array( $rows ) ? $rows : array() as $row ) {
				$reason = self::redact_reason( (string) $row['reason'], $user->user_login, $user->user_email, $user->ID, (string) $row['rule'] );
				if ( false === $reason ) {
					++$bad;
					continue;
				}
				if ( null === $reason ) {
					continue;
				}
				$data = array( 'reason' => $reason );
				if ( LoginGuard::RULE_ID === $row['rule'] ) {
					$data['uri'] = '';
				}
				$wpdb->update( $table, $data, array( 'id' => (int) $row['id'] ) );
				++$result['items_removed'];
			}
		}
		if ( $bad > 0 ) {
			$result['messages'][] = sprintf(
				/* translators: %d: number of log entries. */
				_n( '%d security log entry could not be processed and still holds personal data.', '%d security log entries could not be processed and still hold personal data.', $bad, 'wp-bouncer' ),
				$bad
			);
		}

		$result['done'] = $to > $hi;
		if ( $result['done'] ) {
			delete_transient( $key );
			$result['items_retained'] = true;
			$result['messages'][]     = sprintf(
				/* translators: %d: number of days. */
				__( 'Security log entries are kept for up to %d days to protect the site (legitimate interest) and then deleted automatically: the IP address, country, browser and time of a request stay in them. Names and email addresses in them have been removed.', 'wp-bouncer' ),
				(int) $this->plugin->settings()->get( 'log_retention_days' )
			);
			$this->audit_erasure( $user->ID );
		}
		return $result;
	}

	/**
	 * Leave one audit row for a completed erasure. It uses the alert path, so the
	 * log budget never drops it.
	 *
	 * @param int $user_id User whose data was erased.
	 */
	private function audit_erasure( int $user_id ): void {
		$admin = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		$by    = $admin && $admin->exists() ? $admin->user_login : 'unknown';
		$by_id = $admin && $admin->exists() ? (int) $admin->ID : 0;
		$this->plugin->log_writer()->record(
			array(
				'rule'   => AlertNotifier::LOG_RULE,
				'action' => BlockLogInterface::ACTION_ALERT,
				'reason' => sprintf( 'Personal data erased for user ID %d (request by %s, user ID %d)', $user_id, $by, $by_id ),
			)
		);
	}

	/** Suggest privacy-policy text. */
	public function add_policy_text(): void {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		wp_add_privacy_policy_content( 'WP Bouncer', wp_kses_post( $this->policy_html() ) );
	}

	/**
	 * Policy text for the current settings.
	 */
	public function policy_html(): string {
		$settings = $this->plugin->settings();
		$days     = (int) $settings->get( 'log_retention_days' );
		$traffic  = (array) $settings->get( 'traffic' );

		$html  = '<h2>' . esc_html__( 'Security logging (WP Bouncer)', 'wp-bouncer' ) . '</h2>';
		$html .= '<p>' . esc_html(
			sprintf(
				/* translators: %d: number of days. */
				__( 'To protect this site against attacks, our security plugin records information about requests it blocks or treats as suspicious: your IP address, the approximate country it belongs to, the page address you requested, your browser\'s User-Agent, the time, and why the request was flagged. If you try to log in and fail repeatedly, the username you typed may be recorded. These records are kept for %d days and then deleted automatically.', 'wp-bouncer' ),
				$days
			)
		) . '</p>';
		if ( ! empty( $traffic['enabled'] ) ) {
			$html .= '<p>' . esc_html(
				sprintf(
					/* translators: %d: number of days. */
					__( 'For troubleshooting we also record every page request for %d days: IP address, page address and referring page (with passwords and access tokens removed), User-Agent, response code and, if you are logged in, your user ID.', 'wp-bouncer' ),
					(int) ( $traffic['retention_days'] ?? 7 )
				)
			) . '</p>';
		}
		$html .= '<p>' . esc_html__( 'An activity log also records changes to administrator accounts and to the site (for example a new administrator, a role change or a plugin change): the account\'s username and user ID, the username of the administrator who made the change, and that person\'s IP address and browser details.', 'wp-bouncer' ) . '</p>';
		if ( ! empty( ( (array) $settings->get( 'alerts' ) )['record_admin_logins'] ) ) {
			$html .= '<p>' . esc_html(
				sprintf(
					/* translators: 1: days login rows are kept, 2: days the location history is kept. */
					__( 'When an administrator logs in, we record the account\'s username and user ID, the IP address, approximate country, browser, time and login method, kept for %1$d days. To spot logins from unusual places we keep, for each administrator, the network ranges (not full addresses) and countries used in the last %2$d days.', 'wp-bouncer' ),
					$days,
					AdminLoginRecorder::window_days()
				)
			) . '</p>';
		}
		$html .= '<p>' . esc_html__( 'Your IP address may be held for a short time (minutes to days) to count failed logins and temporary bans.', 'wp-bouncer' ) . '</p>';
		$html .= '<p>' . esc_html__( 'This information is not shared with anyone. Country lookups use a database stored on this site, and the plugin does not contact any outside service about visitors. Site administrators may receive email alerts about security events (for example a new administrator account), which include the IP address and browser details of the person who triggered them, the username and email address of the affected account, and the login of the administrator who made the change.', 'wp-bouncer' ) . '</p>';
		$html .= '<p>' . esc_html__( 'We process this information on the basis of our legitimate interest in keeping the site and its users secure.', 'wp-bouncer' ) . '</p>';
		return $html;
	}
}

// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
