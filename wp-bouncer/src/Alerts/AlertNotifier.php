<?php
/**
 * Emails the site owner about new administrators and plugin changes.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Alerts;

use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Settings (settings['alerts']):
 * - enabled (bool)
 * - recipients (string[]): empty means the site's admin email.
 * - new_admin (bool): an account becomes an administrator (created or promoted).
 * - plugin_changes (bool): a plugin is installed, activated, deactivated or deleted.
 * - plugin_updates (bool): a plugin is updated (off by default: updates are routine).
 *
 * Events are collected during the request and sent as one email at the end
 * of it, so installing and activating a plugin is one email, not two. At most
 * MAX_PER_HOUR emails go out per hour; every event is also written to the
 * Activity Log with action "alert", so nothing is lost if mail is throttled
 * or fails.
 *
 * Alerts keep working while WP_BOUNCER_DISABLE is on: they never block anything.
 */
final class AlertNotifier {

	public const LOG_RULE = 'alerts';

	private const MAX_PER_HOUR = 20;
	private const THROTTLE_KEY = 'wpb_alert_count';

	private Plugin $plugin;

	/** @var array<int, array{type: string, title: string, detail: string, key?: string}> */
	private array $queue = array();

	private bool $shutdown_hooked = false;

	/**
	 * @param Plugin $plugin Plugin.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/** Hook into WordPress. */
	public function register(): void {
		add_action( 'user_register', array( $this, 'on_user_register' ), 20, 1 );
		add_action( 'set_user_role', array( $this, 'on_set_user_role' ), 20, 3 );
		add_action( 'add_user_role', array( $this, 'on_add_user_role' ), 20, 2 );
		add_action( 'granted_super_admin', array( $this, 'on_granted_super_admin' ), 20, 1 );

		add_action( 'activated_plugin', array( $this, 'on_activated_plugin' ), 20, 2 );
		add_action( 'deactivated_plugin', array( $this, 'on_deactivated_plugin' ), 20, 2 );
		add_action( 'deleted_plugin', array( $this, 'on_deleted_plugin' ), 20, 2 );
		add_action( 'upgrader_process_complete', array( $this, 'on_upgrader_complete' ), 20, 2 );
	}

	/** @return array<string, mixed> */
	private function settings(): array {
		$s = $this->plugin->settings()->get( 'alerts' );
		return is_array( $s ) ? $s : array();
	}

	/**
	 * Is this kind of alert switched on?
	 *
	 * @param string $kind new_admin|plugin_changes|plugin_updates.
	 */
	private function wants( string $kind ): bool {
		$s = $this->settings();
		return ! empty( $s['enabled'] ) && ! empty( $s[ $kind ] );
	}

	/* ------------------------------------------------------------------
	 * Administrators
	 * ---------------------------------------------------------------- */

	/**
	 * A new account; alert if it can manage the site.
	 *
	 * @param int $user_id User id.
	 */
	public function on_user_register( $user_id ): void {
		if ( $this->wants( 'new_admin' ) && user_can( (int) $user_id, 'manage_options' ) ) {
			$this->queue_admin( (int) $user_id, 'New administrator account created' );
		}
	}

	/**
	 * A role change. Alert when the new role can manage the site and the old ones couldn't.
	 *
	 * @param int      $user_id   User id.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Previous roles.
	 */
	public function on_set_user_role( $user_id, $role, $old_roles = array() ): void {
		if ( ! $this->wants( 'new_admin' ) || ! self::role_is_admin( (string) $role ) ) {
			return;
		}
		foreach ( (array) $old_roles as $old ) {
			if ( self::role_is_admin( (string) $old ) ) {
				return;
			}
		}
		$this->queue_admin( (int) $user_id, empty( $old_roles ) ? 'New administrator account created' : 'Account promoted to administrator' );
	}

	/**
	 * A role added on top of others.
	 *
	 * @param int    $user_id User id.
	 * @param string $role    Added role.
	 */
	public function on_add_user_role( $user_id, $role ): void {
		if ( $this->wants( 'new_admin' ) && self::role_is_admin( (string) $role ) ) {
			$this->queue_admin( (int) $user_id, 'Account given the administrator role' );
		}
	}

	/**
	 * Multisite: super admin granted.
	 *
	 * @param int $user_id User id.
	 */
	public function on_granted_super_admin( $user_id ): void {
		if ( $this->wants( 'new_admin' ) ) {
			$user = get_userdata( (int) $user_id );
			$this->queue( 'admin', 'Account made a network super admin', $user ? 'Username: ' . $user->user_login . ', user ID ' . (int) $user_id : 'User ID ' . (int) $user_id, 'super|' . (int) $user_id );
		}
	}

	/**
	 * Can this role manage the site?
	 *
	 * @param string $role Role slug.
	 */
	private static function role_is_admin( string $role ): bool {
		if ( 'administrator' === $role ) {
			return true;
		}
		$object = function_exists( 'get_role' ) ? get_role( $role ) : null;
		return $object && $object->has_cap( 'manage_options' );
	}

	/**
	 * Queue one line per user, whichever hooks fired.
	 *
	 * Creating an administrator fires "role added", "role set" and "user
	 * registered", in that order; promoting one fires "role added" then "role
	 * set". The most specific title wins.
	 *
	 * @param int    $user_id User id.
	 * @param string $title   What happened.
	 */
	private function queue_admin( int $user_id, string $title ): void {
		$rank = array(
			'Account given the administrator role' => 1,
			'Account promoted to administrator'    => 2,
			'New administrator account created'    => 3,
		);
		$key  = 'admin|' . $user_id;
		foreach ( $this->queue as $i => $event ) {
			if ( ( $event['key'] ?? '' ) === $key ) {
				if ( ( $rank[ $title ] ?? 0 ) > ( $rank[ $event['title'] ] ?? 0 ) ) {
					$this->queue[ $i ]['title'] = $title;
				}
				return;
			}
		}
		$user   = get_userdata( $user_id );
		$detail = $user ? sprintf( 'Username: %s, email: %s, user ID %d', $user->user_login, $user->user_email, $user_id ) : 'User ID ' . $user_id;
		$this->queue( 'admin', $title, $detail, $key );
	}

	/* ------------------------------------------------------------------
	 * Plugins
	 * ---------------------------------------------------------------- */

	/**
	 * @param string $plugin       Plugin file.
	 * @param bool   $network_wide Network activation.
	 */
	public function on_activated_plugin( $plugin, $network_wide = false ): void {
		if ( $this->wants( 'plugin_changes' ) ) {
			$this->queue( 'plugin', 'Plugin activated: ' . $this->plugin_name( (string) $plugin ), $this->plugin_detail( (string) $plugin, (bool) $network_wide ) );
		}
	}

	/**
	 * @param string $plugin       Plugin file.
	 * @param bool   $network_wide Network deactivation.
	 */
	public function on_deactivated_plugin( $plugin, $network_wide = false ): void {
		if ( $this->wants( 'plugin_changes' ) ) {
			$title = plugin_basename( $this->plugin->file() ) === $plugin ? 'WP Bouncer itself was deactivated' : 'Plugin deactivated: ' . $this->plugin_name( (string) $plugin );
			$this->queue( 'plugin', $title, $this->plugin_detail( (string) $plugin, (bool) $network_wide ) );
		}
	}

	/**
	 * @param string $plugin  Plugin file.
	 * @param bool   $deleted Whether it was deleted.
	 */
	public function on_deleted_plugin( $plugin, $deleted ): void {
		if ( $deleted && $this->wants( 'plugin_changes' ) ) {
			$this->queue( 'plugin', 'Plugin deleted: ' . $plugin, '' );
		}
	}

	/**
	 * Installs and updates.
	 *
	 * @param object               $upgrader   Upgrader.
	 * @param array<string, mixed> $hook_extra Context: type, action, plugins.
	 */
	public function on_upgrader_complete( $upgrader, $hook_extra ): void {
		if ( ! is_array( $hook_extra ) || 'plugin' !== ( $hook_extra['type'] ?? '' ) ) {
			return;
		}
		$action = (string) ( $hook_extra['action'] ?? '' );
		if ( 'install' === $action && $this->wants( 'plugin_changes' ) ) {
			$file = is_object( $upgrader ) && method_exists( $upgrader, 'plugin_info' ) ? (string) $upgrader->plugin_info() : '';
			$this->queue( 'plugin', 'Plugin installed: ' . ( '' !== $file ? $this->plugin_name( $file ) : 'unknown' ), '' !== $file ? $this->plugin_detail( $file, false ) : '' );
		} elseif ( 'update' === $action && $this->wants( 'plugin_updates' ) ) {
			$files = isset( $hook_extra['plugins'] ) ? (array) $hook_extra['plugins'] : ( isset( $hook_extra['plugin'] ) ? array( $hook_extra['plugin'] ) : array() );
			foreach ( $files as $file ) {
				$this->queue( 'plugin', 'Plugin updated: ' . $this->plugin_name( (string) $file ), $this->plugin_detail( (string) $file, false ) );
			}
		}
	}

	/**
	 * Plugin's display name.
	 *
	 * @param string $file Plugin file relative to the plugins folder.
	 */
	private function plugin_name( string $file ): string {
		$name = (string) ( $this->plugin_data( $file )['Name'] ?? '' );
		return '' !== $name ? $name : $file;
	}

	/**
	 * @param string $file    Plugin file.
	 * @param bool   $network Network-wide.
	 */
	private function plugin_detail( string $file, bool $network ): string {
		$data   = $this->plugin_data( $file );
		$detail  = $file;
		$version = (string) ( $data['Version'] ?? '' );
		if ( '' !== $version ) {
			$detail .= ', version ' . $version;
		}
		return $detail . ( $network ? ', network-wide' : '' );
	}

	/**
	 * @param string $file Plugin file.
	 * @return array<string, bool|string> Header fields from get_plugin_data().
	 */
	private function plugin_data( string $file ): array {
		$path = WP_PLUGIN_DIR . '/' . $file;
		if ( '' === $file || ! is_file( $path ) ) {
			return array();
		}
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		return (array) get_plugin_data( $path, false, false );
	}

	/* ------------------------------------------------------------------
	 * Queue, send, log
	 * ---------------------------------------------------------------- */

	/**
	 * @param string $type   admin|plugin.
	 * @param string $title  What happened.
	 * @param string $detail More detail.
	 * @param string $key    De-duplication key.
	 */
	private function queue( string $type, string $title, string $detail, string $key = '' ): void {
		$event = array(
			'type'   => $type,
			'title'  => $title,
			'detail' => $detail,
		);
		if ( '' !== $key ) {
			$event['key'] = $key;
		}
		$this->queue[] = $event;
		if ( ! $this->shutdown_hooked ) {
			add_action( 'shutdown', array( $this, 'flush' ) );
			$this->shutdown_hooked = true;
		}
	}

	/** Send everything collected during this request. */
	public function flush(): void {
		$events      = AlertFormatter::dedupe( $this->queue );
		$this->queue = array();
		if ( empty( $events ) ) {
			return;
		}
		$context = $this->context();
		foreach ( $events as $event ) {
			$this->log( $event, $context );
		}

		$sent = (int) get_transient( self::THROTTLE_KEY );
		if ( $sent >= self::MAX_PER_HOUR ) {
			return;
		}
		set_transient( self::THROTTLE_KEY, $sent + 1, HOUR_IN_SECONDS );

		$mail = AlertFormatter::format( $events, $context );
		wp_mail( $this->recipients(), $mail['subject'], $mail['body'] );
	}

	/**
	 * Send a test email.
	 *
	 * @return true|string True, or why it failed.
	 */
	public function send_test() {
		$error   = '';
		$capture = static function ( $wp_error ) use ( &$error ): void {
			$error = is_object( $wp_error ) && method_exists( $wp_error, 'get_error_message' ) ? (string) $wp_error->get_error_message() : 'unknown error';
		};
		add_action( 'wp_mail_failed', $capture );
		$mail = AlertFormatter::format(
			array(
				array(
					'type'   => 'test',
					'title'  => 'Test alert',
					'detail' => 'This is a test from Bouncer → General → Email alerts. Real alerts look like this.',
				),
			),
			$this->context()
		);
		$ok = wp_mail( $this->recipients(), $mail['subject'], $mail['body'] );
		remove_action( 'wp_mail_failed', $capture );
		if ( $ok ) {
			return true;
		}
		return '' !== $error ? $error : __( 'WordPress could not send the email. Check your site\'s mail setup (an SMTP plugin is often needed).', 'wp-bouncer' );
	}

	/** @return string[] Where alerts go. */
	public function recipients(): array {
		$list = (array) ( $this->settings()['recipients'] ?? array() );
		return ! empty( $list ) ? array_values( $list ) : array( (string) get_option( 'admin_email' ) );
	}

	/** @return array<string, string> Who, where, when. */
	private function context(): array {
		$user    = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		$actor   = $user && $user->exists() ? sprintf( '%s (user ID %d)', $user->user_login, $user->ID ) : 'no logged-in user (WP-CLI, a scheduled task, or code)';
		$request = $this->plugin->current_request();
		$ip      = ( defined( 'WP_CLI' ) && WP_CLI ) ? '' : $request->ip();
		return array(
			'site_name'    => wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ),
			'site_url'     => home_url( '/' ),
			'time'         => wp_date( 'Y-m-d H:i:s T' ),
			'actor'        => $actor,
			'ip'           => '' !== $ip ? $ip : ( ( defined( 'WP_CLI' ) && WP_CLI ) ? 'command line' : '' ),
			'country'      => '' !== $ip ? (string) $this->plugin->geo()->lookup( $ip ) : '',
			'user_agent'   => ( defined( 'WP_CLI' ) && WP_CLI ) ? '' : $request->user_agent(),
			'settings_url' => admin_url( 'admin.php?page=wp-bouncer&tab=general#wpb-alerts' ),
		);
	}

	/**
	 * Write an event to the Activity Log.
	 *
	 * @param array{type: string, title: string, detail: string} $event   Event.
	 * @param array<string, string>                              $context Context.
	 */
	private function log( array $event, array $context ): void {
		$request = $this->plugin->current_request();
		$this->plugin->log()->record(
			array(
				'ip'         => $context['ip'],
				'country'    => $context['country'],
				'rule'       => self::LOG_RULE,
				'action'     => BlockLogInterface::ACTION_ALERT,
				'reason'     => $event['title'] . ( '' !== $event['detail'] ? ' — ' . $event['detail'] : '' ) . ' — by ' . $context['actor'],
				'method'     => ( defined( 'WP_CLI' ) && WP_CLI ) ? 'CLI' : $request->method(),
				'uri'        => ( defined( 'WP_CLI' ) && WP_CLI ) ? '' : $request->uri(),
				'user_agent' => $context['user_agent'],
			)
		);
	}
}
