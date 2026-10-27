<?php
/**
 * Personal-data exporter and eraser for administrator login rows and location history.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Privacy;

use WPBouncer\AdminLogins\AdminLoginRecorder;
use WPBouncer\AdminLogins\LoginEvent;
use WPBouncer\AdminLogins\LoginHistoryRepository;
use WPBouncer\Alerts\AlertNotifier;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Plugin;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own log table; personal data must not be served from a cache.

/**
 * Login rows are matched without a user_id column: rule "admin_login", action
 * "login" and a reason that starts with "User ID N:" (only the recorder writes
 * those rows). Rows are deleted, not redacted. On multisite the callbacks act
 * on the current site only.
 */
final class AdminLoginPrivacy {

	/** Rows per exporter or eraser page. */
	public const PAGE = 500;

	/** Exporter and eraser id. */
	public const ID = 'wp-bouncer-admin-logins';

	/**
	 * History storage.
	 *
	 * @var LoginHistoryRepository
	 */
	private LoginHistoryRepository $history;

	/**
	 * Plugin, for the audit row. Null in tests that don't need it.
	 *
	 * @var Plugin|null
	 */
	private ?Plugin $plugin;

	/**
	 * Set up the AdminLoginPrivacy.
	 *
	 * @param LoginHistoryRepository|null $history History storage.
	 * @param Plugin|null                 $plugin  Plugin, used to write the audit row.
	 */
	public function __construct( ?LoginHistoryRepository $history = null, ?Plugin $plugin = null ) {
		$this->history = $history ?? new LoginHistoryRepository();
		$this->plugin  = $plugin;
	}

	/** Hook into the WordPress privacy tools. */
	public function register(): void {
		add_filter( 'wp_privacy_personal_data_exporters', array( $this, 'add_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( $this, 'add_eraser' ) );
	}

	/**
	 * Register the exporter.
	 *
	 * @param mixed $exporters Registered exporters.
	 * @return array<string, mixed>
	 */
	public function add_exporter( $exporters ): array {
		$exporters             = is_array( $exporters ) ? $exporters : array();
		$exporters[ self::ID ] = array(
			'exporter_friendly_name' => __( 'Site security: administrator logins', 'wp-bouncer' ),
			'callback'               => array( $this, 'export' ),
		);
		return $exporters;
	}

	/**
	 * Register the eraser.
	 *
	 * @param mixed $erasers Registered erasers.
	 * @return array<string, mixed>
	 */
	public function add_eraser( $erasers ): array {
		$erasers             = is_array( $erasers ) ? $erasers : array();
		$erasers[ self::ID ] = array(
			'eraser_friendly_name' => __( 'Site security: administrator logins', 'wp-bouncer' ),
			'callback'             => array( $this, 'erase' ),
		);
		return $erasers;
	}

	/**
	 * Login-method label found in a stored reason ('' when none).
	 *
	 * @param string $reason Stored reason.
	 */
	public static function method_from_reason( string $reason ): string {
		$found = '';
		foreach ( LoginEvent::methods() as $method ) {
			if ( false !== strpos( $reason, ' — ' . $method ) && strlen( $method ) > strlen( $found ) ) {
				$found = $method;
			}
		}
		return $found;
	}

	/**
	 * The log table.
	 */
	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'bouncer_log';
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
	 * SQL LIKE pattern for one user's rows.
	 *
	 * @param int $user_id User ID.
	 */
	private function like( int $user_id ): string {
		global $wpdb;
		return $wpdb->esc_like( LoginEvent::reason_prefix( $user_id ) ) . '%';
	}

	/**
	 * Export a user's location history (page 1) and login rows.
	 *
	 * @param string $email Email address of the requester.
	 * @param int    $page  Page, from 1.
	 * @return array{data: array<int, array<string, mixed>>, done: bool}
	 */
	public function export( $email, $page = 1 ): array {
		global $wpdb;
		$user = $this->user( (string) $email );
		if ( null === $user ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}
		$page = max( 1, (int) $page );
		$data = array();

		if ( 1 === $page ) {
			$history = $this->history->load( (int) $user->ID );
			if ( null !== $history ) {
				$data[] = array(
					'group_id'    => self::ID,
					'group_label' => __( 'Site security: administrator logins', 'wp-bouncer' ),
					'item_id'     => self::ID . '-history-since',
					'data'        => array(
						array(
							'name'  => __( 'Login history kept since (UTC)', 'wp-bouncer' ),
							'value' => gmdate( 'Y-m-d H:i:s', $history->since() ),
						),
					),
				);
				foreach ( $history->entries() as $i => $entry ) {
					$data[] = array(
						'group_id'    => self::ID,
						'group_label' => __( 'Site security: administrator logins', 'wp-bouncer' ),
						'item_id'     => self::ID . '-history-' . (int) $i,
						'data'        => array(
							array(
								'name'  => __( 'IP range', 'wp-bouncer' ),
								'value' => $entry['r'],
							),
							array(
								'name'  => __( 'Country', 'wp-bouncer' ),
								'value' => $entry['c'],
							),
							array(
								'name'  => __( 'Last seen (UTC)', 'wp-bouncer' ),
								'value' => gmdate( 'Y-m-d H:i:s', $entry['t'] ),
							),
						),
					);
				}
			}
		}

		$key    = 'wp_bouncer_export_' . md5( 'logins|' . $user->ID . '|' . $page );
		$cursor = $page > 1 ? get_transient( $key ) : 0;
		$offset = false === $cursor ? ( $page - 1 ) * self::PAGE : 0;
		$after  = false === $cursor ? 0 : (int) $cursor;
		$rows   = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, created_at, ip, country, reason, user_agent FROM %i WHERE rule = %s AND action = %s AND reason LIKE %s AND id > %d ORDER BY id LIMIT %d OFFSET %d',
				$this->table(),
				AdminLoginRecorder::LOG_RULE,
				BlockLogInterface::ACTION_LOGIN,
				$this->like( (int) $user->ID ),
				$after,
				self::PAGE,
				$offset
			),
			ARRAY_A
		);
		$rows   = is_array( $rows ) ? $rows : array();
		foreach ( $rows as $row ) {
			$data[] = array(
				'group_id'          => self::ID,
				'group_label'       => __( 'Site security: administrator logins', 'wp-bouncer' ),
				'group_description' => __( 'Logins to administrator accounts, kept in the Activity Log.', 'wp-bouncer' ),
				'item_id'           => self::ID . '-' . (int) $row['id'],
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
						'name'  => __( 'Country', 'wp-bouncer' ),
						'value' => (string) $row['country'],
					),
					array(
						'name'  => __( 'Login method', 'wp-bouncer' ),
						'value' => self::method_from_reason( (string) $row['reason'] ),
					),
					array(
						'name'  => __( 'Browser (User-Agent)', 'wp-bouncer' ),
						'value' => (string) $row['user_agent'],
					),
				),
			);
		}
		$done = count( $rows ) < self::PAGE;
		if ( ! $done ) {
			set_transient( 'wp_bouncer_export_' . md5( 'logins|' . $user->ID . '|' . ( $page + 1 ) ), (int) end( $rows )['id'], HOUR_IN_SECONDS );
		}
		return array(
			'data' => $data,
			'done' => $done,
		);
	}

	/**
	 * Leave one audit row when a user's administrator-login data is erased. It uses the
	 * alert path, so the log budget never drops it.
	 *
	 * @param int $user_id User whose data was erased.
	 */
	private function audit_erasure( int $user_id ): void {
		if ( null === $this->plugin ) {
			return;
		}
		$admin = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		$by    = $admin && $admin->exists() ? LoginEvent::clean_login( (string) $admin->user_login ) : 'unknown';
		$by_id = $admin && $admin->exists() ? (int) $admin->ID : 0;
		$this->plugin->log_writer()->record(
			array(
				'rule'   => AlertNotifier::LOG_RULE,
				'action' => BlockLogInterface::ACTION_ALERT,
				'reason' => sprintf( 'Administrator login data erased for user ID %d (request by %s, user ID %d); the next login from a new location will alert', $user_id, $by, $by_id ),
			)
		);
	}

	/**
	 * Delete a user's login rows (one batch per call) and location history.
	 *
	 * @param string $email Email address of the requester.
	 * @param int    $page  Page from 1. Deleted rows drop out of the next select; the audit row is written on page 1.
	 * @return array{items_removed: int, items_retained: bool, messages: string[], done: bool}
	 */
	public function erase( $email, $page = 1 ): array {
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
		// A tombstone, not a delete: "never recorded" would make the next login silent, which is
		// what an attacker with a stolen password wants. The next login from a new range alerts.
		if ( null !== $this->history->load( (int) $user->ID ) ) {
			$this->history->reset( (int) $user->ID, time() );
		}
		if ( (int) $page <= 1 ) {
			$this->audit_erasure( (int) $user->ID );
		}

		$ids = $wpdb->get_col(
			$wpdb->prepare(
				'SELECT id FROM %i WHERE rule = %s AND action = %s AND reason LIKE %s ORDER BY id LIMIT %d',
				$this->table(),
				AdminLoginRecorder::LOG_RULE,
				BlockLogInterface::ACTION_LOGIN,
				$this->like( (int) $user->ID ),
				self::PAGE
			)
		);
		$ids = array_map( 'intval', is_array( $ids ) ? $ids : array() );
		if ( array() !== $ids ) {
			$placeholders            = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
			$removed                 = $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM %i WHERE id IN ({$placeholders})", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- only %d placeholders are interpolated.
					array_merge( array( $this->table() ), $ids )
				)
			);
			$result['items_removed'] = max( 0, (int) $removed );
		}
		$result['done'] = count( $ids ) < self::PAGE;
		return $result;
	}
}

// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
