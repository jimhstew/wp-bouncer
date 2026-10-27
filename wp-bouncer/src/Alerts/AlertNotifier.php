<?php
/**
 * Emails the site owner about new administrators and plugin changes.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Alerts;

use WPBouncer\AdminLogins\LoginAssessment;
use WPBouncer\AdminLogins\LoginEvent;
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
 * - firewall_changes (bool): risky settings changes, and the WP_BOUNCER_DISABLE reminder (on by default).
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

	private const MAX_PER_HOUR          = 20;
	private const THROTTLE_KEY          = 'wpb_alert_count';
	private const MAX_CRITICAL_PER_HOUR = 20;
	private const THROTTLE_KEY_CRITICAL = 'wpb_alert_count_critical';
	/** Settings-change alerts have their own hourly cap, so they can't use up the critical budget. */
	private const MAX_SETTINGS_PER_HOUR   = 10;
	private const THROTTLE_KEY_SETTINGS   = 'wpb_alert_count_settings';
	private const THROTTLE_KEY_SET_NOTICE = 'wpb_alert_settings_notice';
	/** Administrator-login alerts have their own hourly cap, so they can't use up any other budget. */
	private const MAX_LOGIN_PER_HOUR      = 10;
	private const THROTTLE_KEY_LOGIN      = 'wpb_alert_count_login';
	private const THROTTLE_KEY_LOGIN_NOTE = 'wpb_alert_login_notice';
	/** Most new-location emails per administrator and hour. */
	private const MAX_LOGIN_PER_USER_HOUR = 3;
	/** Ceiling on uncapped (alert-silencing) settings alerts per blog and hour; above it the normal settings cap applies. */
	private const MAX_UNCAPPED_PER_HOUR   = 50;
	private const THROTTLE_KEY_UNCAPPED   = 'wpb_alert_uncapped';
	public const DISABLED_REMINDER_OPTION = 'wpb_disabled_alerted';

	/**
	 * Plugin instance.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Tells whether WP_BOUNCER_DISABLE is on (replaceable in tests).
	 *
	 * @var \Closure
	 */
	private \Closure $is_disabled;

	/**
	 * Alerts waiting to be sent at shutdown.
	 *
	 * @var array<int, array{type: string, title: string, detail: string, key?: string}>
	 */
	private array $queue = array();

	/**
	 * Whether the shutdown hook is registered.
	 *
	 * @var bool
	 */
	private bool $shutdown_hooked = false;

	/**
	 * Set up the AlertNotifier.
	 *
	 * @param Plugin        $plugin      Plugin.
	 * @param callable|null $is_disabled Returns true while the emergency switch is on; defaults to Plugin::is_disabled().
	 */
	public function __construct( Plugin $plugin, ?callable $is_disabled = null ) {
		$this->plugin      = $plugin;
		$this->is_disabled = null === $is_disabled ? Plugin::is_disabled( ... ) : \Closure::fromCallable( $is_disabled );
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

	/**
	 * Get this component's settings.
	 *
	 * @return array<string, mixed>
	 */
	private function settings(): array {
		$s = $this->plugin->settings()->get( 'alerts' );
		return is_array( $s ) ? $s : array();
	}

	/**
	 * Is this kind of alert switched on?
	 *
	 * @param string                    $kind   new_admin|plugin_changes|plugin_updates|firewall_changes|admin_login_location.
	 * @param array<string, mixed>|null $alerts Alert settings to judge by instead of the loaded ones.
	 */
	private function wants( string $kind, ?array $alerts = null ): bool {
		$s = $alerts ?? $this->settings();
		return ! empty( $s['enabled'] ) && ! empty( $s[ $kind ] );
	}

	/*
	 * ------------------------------------------------------------------
	 * Administrators
	 * ----------------------------------------------------------------
	 */

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
	 * Decide what happens to the new-location email for a login, and count it against
	 * the administrator's hourly cap. Call once per login, before writing the row.
	 *
	 * @param LoginEvent      $e The login.
	 * @param LoginAssessment $a What was found.
	 * @return string "none" (alerts off or vetoed), "send", or "throttled" (over the per-user cap).
	 */
	public function check_admin_login( LoginEvent $e, LoginAssessment $a ): string {
		if ( ! $this->wants( 'admin_login_location' ) ) {
			return 'none';
		}
		$flags = array(
			'first'       => $a->first,
			'new_range'   => $a->new_range,
			'new_country' => $a->new_country,
			'reliable'    => true,
		);
		/**
		 * Filters whether the new-location email is sent for an administrator login.
		 *
		 * @param bool  $send  Default true.
		 * @param array $event Keys user_id, login, ip, range, country, method, time.
		 * @param array $flags Keys first, new_range, new_country, reliable.
		 */
		if ( ! apply_filters( 'wp_bouncer_admin_login_alert', true, $e->to_array(), $flags ) ) {
			return 'none';
		}
		return $this->plugin->store()->increment( 'login_alert:' . $e->user_id, HOUR_IN_SECONDS ) > self::MAX_LOGIN_PER_USER_HOUR ? 'throttled' : 'send';
	}

	/**
	 * An administrator logged in from a range or country not in their history.
	 *
	 * @param LoginEvent      $e        The login.
	 * @param LoginAssessment $a        What was found.
	 * @param bool            $logged   Whether the Activity Log row was written. When it wasn't, the alert row is.
	 * @param string|null     $decision Result of check_admin_login() when the caller already asked, else null.
	 * @return bool Whether an email was queued.
	 */
	public function on_admin_login( LoginEvent $e, LoginAssessment $a, bool $logged = true, ?string $decision = null ): bool {
		$decision = $decision ?? $this->check_admin_login( $e, $a );
		if ( 'none' === $decision ) {
			return false;
		}
		$extra      = array( 'ctx' => array( 'actor' => sprintf( '%s (user ID %d)', $e->login, $e->user_id ) ) );
		$recipients = array();
		$key        = 'login|' . $e->user_id;
		if ( is_multisite() ) {
			// A login assessed on another site is reported as that site, with that site's recipients.
			$extra['blog'] = get_current_blog_id();
			$extra['ctx'] += array(
				'site_name'    => wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ),
				'site_url'     => home_url( '/' ),
				'settings_url' => admin_url( 'admin.php?page=wp-bouncer&tab=general#wpb-alerts' ),
			);
			$recipients    = $this->recipients();
			$key          .= '|' . get_current_blog_id();
		}
		if ( 'throttled' === $decision ) {
			$extra['capped'] = true;
		}
		$this->queue(
			'login',
			'Administrator login from a new location',
			$e->email_detail( $a ),
			$key,
			'',
			false,
			$logged,
			$recipients,
			$extra
		);
		return 'send' === $decision;
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
		// The email may name the address; the stored Activity Log row never does.
		$log_detail = $user ? sprintf( 'Username: %s, user ID %d', $user->user_login, $user_id ) : 'User ID ' . $user_id;
		$this->queue( 'admin', $title, $detail, $key, $log_detail );
	}

	/*
	 * ------------------------------------------------------------------
	 * Plugins
	 * ----------------------------------------------------------------
	 */

	/**
	 * On activated plugin.
	 *
	 * @param string $plugin       Plugin file.
	 * @param bool   $network_wide Network activation.
	 */
	public function on_activated_plugin( $plugin, $network_wide = false ): void {
		if ( $this->wants( 'plugin_changes' ) ) {
			$this->queue( 'plugin', 'Plugin activated: ' . $this->plugin_name( (string) $plugin ), $this->plugin_detail( (string) $plugin, (bool) $network_wide ) );
		}
	}

	/**
	 * On deactivated plugin.
	 *
	 * @param string $plugin       Plugin file.
	 * @param bool   $network_wide Network deactivation.
	 */
	public function on_deactivated_plugin( $plugin, $network_wide = false ): void {
		if ( $this->wants( 'plugin_changes' ) ) {
			$title = plugin_basename( $this->plugin->file() ) === $plugin ? 'WP Bouncer itself was deactivated' : 'Plugin deactivated: ' . $this->plugin_name( (string) $plugin );
			$this->queue( 'plugin', $title, $this->plugin_detail( (string) $plugin, (bool) $network_wide ), '', '', plugin_basename( $this->plugin->file() ) === $plugin );
		}
	}

	/**
	 * On deleted plugin.
	 *
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
	 * Plugin detail.
	 *
	 * @param string $file    Plugin file.
	 * @param bool   $network Network-wide.
	 */
	private function plugin_detail( string $file, bool $network ): string {
		$data    = $this->plugin_data( $file );
		$detail  = $file;
		$version = (string) ( $data['Version'] ?? '' );
		if ( '' !== $version ) {
			$detail .= ', version ' . $version;
		}
		return $detail . ( $network ? ', network-wide' : '' );
	}

	/**
	 * Plugin data.
	 *
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

	/*
	 * ------------------------------------------------------------------
	 * Firewall configuration
	 * ----------------------------------------------------------------
	 */

	/**
	 * Queue an alert for risky settings changes (own hourly cap, separate from the critical budget).
	 *
	 * Call this BEFORE the new settings are loaded: whether to alert, and who
	 * gets it, come from the settings in force until now. Otherwise one save
	 * that switches alerts off, or points them at another address, would
	 * silence or redirect its own alert. When the recipients changed, both the
	 * old and the new addresses are mailed.
	 *
	 * The caller has already written the audit row to the Activity Log, so the
	 * event is marked as logged. Only key paths are named, never values.
	 *
	 * @param string[]                  $risky        The risky changed key paths (see SettingsDiff::risky()).
	 * @param string[]                  $all          Every changed key path.
	 * @param array<string, mixed>      $new_settings The settings being saved.
	 * @param array<string, mixed>|null $old_settings The settings before the write. When given, whether to
	 *                                           alert and the base recipients come from its "alerts" part, not from
	 *                                           the loaded settings (which can be stale under WP-CLI, or belong to another blog).
	 * @param string|null               $actor        Who did it, from the same builder as the Activity Log row.
	 * @param bool                      $row_written  False when the Activity Log row could not be written (the alert says so).
	 */
	public function on_risky_settings_change( array $risky, array $all, array $new_settings = array(), ?array $old_settings = null, ?string $actor = null, bool $row_written = true ): void {
		$old_alerts = null;
		if ( null !== $old_settings ) {
			$old_alerts = isset( $old_settings['alerts'] ) && is_array( $old_settings['alerts'] ) ? $old_settings['alerts'] : array();
		}
		if ( empty( $risky ) || ! $this->wants( 'firewall_changes', $old_alerts ) ) {
			return;
		}
		$detail = 'Risky: ' . implode( ', ', $risky );
		$other  = array_values( array_diff( $all, $risky ) );
		if ( ! empty( $other ) ) {
			$detail .= '. Also changed: ' . implode( ', ', $other );
		}
		if ( ! $row_written ) {
			$detail .= '. The Activity Log row could not be written.';
		}
		$new_alerts = isset( $new_settings['alerts'] ) && is_array( $new_settings['alerts'] ) ? $new_settings['alerts'] : array();
		// Own hourly cap (not the critical budget); site details are fixed now, not at shutdown.
		$ctx = array(
			'site_name'    => wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ),
			'site_url'     => home_url( '/' ),
			'settings_url' => admin_url( 'admin.php?page=wp-bouncer&tab=general#wpb-alerts' ),
		);
		if ( null !== $actor ) {
			$ctx['actor'] = $actor;
		}
		$this->queue(
			'firewall',
			'Firewall settings changed',
			$detail,
			'',
			'',
			false,
			true,
			$this->firewall_recipients( $new_alerts, $old_alerts ),
			array(
				'settings' => true,
				'uncapped' => self::silences_alerts( $risky ),
				'blog'     => get_current_blog_id(),
				'ctx'      => $ctx,
			)
		);
	}

	/**
	 * The Activity Log was emptied: tell the owner (critical). The caller writes the audit row.
	 */
	public function on_log_cleared(): void {
		if ( $this->wants( 'firewall_changes' ) ) {
			$this->queue( 'firewall', 'Activity Log cleared', 'The whole Activity Log was deleted.', 'log_cleared', '', true, true, $this->firewall_recipients() );
		}
	}

	/**
	 * Who gets firewall alerts: the current recipients, the recipients being
	 * saved, and on multisite the network admin.
	 *
	 * @param array<string, mixed>      $new_alerts The alerts settings being saved (empty when none).
	 * @param array<string, mixed>|null $old_alerts The alerts settings before the write; replaces the loaded ones as the base.
	 * @return string[]
	 */
	private function firewall_recipients( array $new_alerts = array(), ?array $old_alerts = null ): array {
		$list = $this->base_recipients( $old_alerts );
		if ( array_key_exists( 'recipients', $new_alerts ) ) {
			$incoming = array_values( (array) $new_alerts['recipients'] );
			$list     = array_merge( $list, ! empty( $incoming ) ? $incoming : array( (string) get_option( 'admin_email' ) ) );
		}
		if ( is_multisite() ) {
			$list[] = (string) get_site_option( 'admin_email' );
		}
		$out = array();
		foreach ( $list as $address ) {
			$address = trim( (string) $address );
			if ( '' !== $address ) {
				$out[ strtolower( $address ) ] = $address;
			}
		}
		return array_values( $out );
	}

	/** Admin request: remind only a signed-in user who manages the plugin. */
	public function on_admin_init(): void {
		if ( current_user_can( 'manage_options' ) ) {
			$this->maybe_remind_disabled();
		}
	}

	/**
	 * While WP_BOUNCER_DISABLE is defined, remind the owner at most once every 24 hours.
	 *
	 * Runs from the daily cron job and (for signed-in managers) from admin
	 * requests, never from the firewall path. The 24 hour slot is claimed
	 * atomically in the options table, so concurrent requests send one mail.
	 */
	public function maybe_remind_disabled(): void {
		if ( ! ( $this->is_disabled )() || ! $this->wants( 'firewall_changes' ) || ! $this->claim_reminder_slot() ) {
			return;
		}
		$this->queue( 'firewall', 'WP Bouncer is switched off (WP_BOUNCER_DISABLE)', 'Nothing is being blocked while this constant is set in wp-config.php. This reminder is sent once a day.', 'disabled', '', true, false, $this->firewall_recipients() );
	}

	/**
	 * Claim the once-a-day slot.
	 *
	 * Adding the option fails if the row exists (unique option name). An old row is
	 * replaced with a compare-and-swap UPDATE on its previous value, so only
	 * one of several racing requests changes a row. Plain SQL that MySQL,
	 * MariaDB and SQLite all run.
	 *
	 * @return bool True if this request owns the slot.
	 */
	private function claim_reminder_slot(): bool {
		global $wpdb;
		$now = (string) time();
		// Two tries: the second covers a row that vanished (or was never visible) between the steps.
		for ( $try = 0; $try < 2; $try++ ) {
			// INSERT IGNORE, not add_option(): core's upsert would let two racing first claims both win.
			$inserted = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO %i (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $wpdb->options, self::DISABLED_REMINDER_OPTION, $now ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- atomic claim, see above.
			if ( 1 === $inserted ) {
				$this->forget_reminder_cache();
				return true;
			}
			$last = $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, self::DISABLED_REMINDER_OPTION ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- read around the object cache on purpose: the claim must see the latest value.
			if ( null === $last ) {
				continue;
			}
			if ( (int) $now - (int) $last < DAY_IN_SECONDS ) {
				return false;
			}
			$won = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value = %s WHERE option_name = %s AND option_value = %s', $wpdb->options, $now, self::DISABLED_REMINDER_OPTION, (string) $last ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- compare-and-swap, see above.
			$this->forget_reminder_cache();
			return 1 === $won;
		}
		return false;
	}

	/** Drop cached copies of the reminder option so get_option() stays coherent after a direct write. */
	private function forget_reminder_cache(): void {
		wp_cache_delete( self::DISABLED_REMINDER_OPTION, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
	}

	/*
	 * ------------------------------------------------------------------
	 * Queue, send, log
	 * ----------------------------------------------------------------
	 */

	/**
	 * Queue.
	 *
	 * @param string               $type   admin|plugin.
	 * @param string               $title  What happened.
	 * @param string               $detail More detail.
	 * @param string               $key    De-duplication key.
	 * @param string               $log_detail Detail for the stored log row, when it must differ from the email.
	 * @param bool                 $critical   Uses the separate email budget (new administrators, WP Bouncer switched off).
	 * @param bool                 $logged     The caller has already written the Activity Log row.
	 * @param string[]             $recipients Addresses to mail instead of the usual recipients.
	 * @param array<string, mixed> $extra Further event fields (settings flag, blog id, site details).
	 */
	private function queue( string $type, string $title, string $detail, string $key = '', string $log_detail = '', bool $critical = false, bool $logged = false, array $recipients = array(), array $extra = array() ): void {
		$event = array(
			'type'   => $type,
			'title'  => $title,
			'detail' => $detail,
		);
		if ( $critical || 'admin' === $type ) {
			$event['critical'] = true;
		}
		if ( $logged ) {
			$event['logged'] = true;
		}
		if ( ! empty( $recipients ) ) {
			$event['recipients'] = $recipients;
		}
		if ( '' !== $key ) {
			$event['key'] = $key;
		}
		if ( '' !== $log_detail ) {
			$event['log_detail'] = $log_detail;
		}
		$this->queue[] = array_merge( $extra, $event );
		if ( ! $this->shutdown_hooked ) {
			add_action( 'shutdown', array( $this, 'flush' ) );
			$this->shutdown_hooked = true;
		}
	}

	/**
	 * Does a change touch what silences or redirects alerts (alerts.*, mode, or the whole option)?
	 *
	 * @param string[] $paths Changed paths.
	 */
	private static function silences_alerts( array $paths ): bool {
		foreach ( $paths as $path ) {
			if ( 'mode' === $path || 'settings' === $path || 0 === strpos( $path, 'alerts.' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Is this event one of the few that get their own email budget?
	 *
	 * @param array{type: string, title: string, detail: string, log_detail?: string, critical?: bool, logged?: bool, recipients?: string[]} $event Event.
	 */
	private static function is_critical( array $event ): bool {
		return ! empty( $event['critical'] );
	}

	/** Send everything collected during this request. */
	public function flush(): void {
		// May be registered at shutdown 10 from inside a priority-0 callback; it still runs in the same do_action.
		$events      = AlertFormatter::dedupe( $this->queue );
		$this->queue = array();
		if ( empty( $events ) ) {
			return;
		}
		$context = $this->context();
		foreach ( $events as $event ) {
			if ( empty( $event['logged'] ) ) {
				if ( isset( $event['blog'] ) && get_current_blog_id() !== (int) $event['blog'] ) {
					// The fallback row belongs to the log of the site the event is about.
					$this->plugin->run_on_site( (int) $event['blog'], fn() => $this->log( $event, $context ) );
				} else {
					$this->log( $event, $context );
				}
			}
		}

		// Cheap plugin events can't use up the email budget of the alerts that matter most:
		// new administrators and WP Bouncer being switched off have their own, and so do
		// settings changes (whoever writes the option, they can't starve the others).
		// Changes that silence or redirect alerts are never capped.
		$keys   = array(
			'general'  => self::THROTTLE_KEY,
			'critical' => self::THROTTLE_KEY_CRITICAL,
			'settings' => self::THROTTLE_KEY_SETTINGS,
			'login'    => self::THROTTLE_KEY_LOGIN,
		);
		$maxes  = array(
			'general'  => self::MAX_PER_HOUR,
			'critical' => self::MAX_CRITICAL_PER_HOUR,
			'settings' => self::MAX_SETTINGS_PER_HOUR,
			'login'    => self::MAX_LOGIN_PER_HOUR,
		);
		$counts = array();
		foreach ( $keys as $bucket => $key ) {
			$counts[ $bucket ] = (int) get_transient( $key );
		}

		// One mail per group. An event from another site than the current one (a switched blog) is
		// reported as that site; everything else is one combined mail, as before.
		$current = get_current_blog_id();
		$groups  = array();
		foreach ( $events as $event ) {
			$ctx = isset( $event['ctx'] ) && is_array( $event['ctx'] ) ? $event['ctx'] : array();
			if ( isset( $event['blog'] ) && (int) $event['blog'] !== $current ) {
				$gkey = (string) wp_json_encode( array( $event['blog'], $ctx ) );
			} else {
				$gkey = '';
				$ctx  = array_intersect_key( $ctx, array( 'actor' => true ) );
			}
			$groups[ $gkey ]['ctx']      = array_merge( $groups[ $gkey ]['ctx'] ?? array(), $ctx );
			$groups[ $gkey ]['events'][] = $event;
		}

		$uncapped      = get_transient( self::THROTTLE_KEY_UNCAPPED );
		$uncapped      = is_array( $uncapped ) ? $uncapped : array();
		$uncapped_used = false;
		$dropped       = array();
		foreach ( $groups as $group ) {
			$send = array();
			$uses = array();
			foreach ( $group['events'] as $event ) {
				$bucket  = ! empty( $event['settings'] ) ? 'settings' : ( 'login' === $event['type'] ? 'login' : ( self::is_critical( $event ) ? 'critical' : 'general' ) );
				$blog_id = (int) ( $event['blog'] ?? $current );
				if ( ! empty( $event['capped'] ) ) {
					// Over the per-administrator cap: counted in the login notice, never mailed.
					$dropped['login'][ $blog_id ][] = $event;
					continue;
				}
				$free = ! empty( $event['uncapped'] ) && ( $uncapped[ $blog_id ] ?? 0 ) < self::MAX_UNCAPPED_PER_HOUR;
				if ( $free ) {
					$uncapped[ $blog_id ] = ( $uncapped[ $blog_id ] ?? 0 ) + 1;
					$uncapped_used        = true;
				}
				if ( $free || $counts[ $bucket ] < $maxes[ $bucket ] ) {
					$send[]          = $event;
					$uses[ $bucket ] = true;
				} elseif ( 'settings' === $bucket || 'login' === $bucket ) {
					$dropped[ $bucket ][ (int) ( $event['blog'] ?? $current ) ][] = $event;
				}
			}
			if ( empty( $send ) ) {
				continue;
			}
			// Each email counts once against every budget it uses.
			foreach ( array_keys( $uses ) as $bucket ) {
				++$counts[ $bucket ];
				set_transient( $keys[ $bucket ], $counts[ $bucket ], HOUR_IN_SECONDS );
			}
			$this->send_mail( $send, array_merge( $context, $group['ctx'] ) );
		}

		if ( $uncapped_used ) {
			set_transient( self::THROTTLE_KEY_UNCAPPED, $uncapped, HOUR_IN_SECONDS );
		}

		// One notice per bucket, site and hour, with only that site's recipients and details; it counts against no cap.
		$notices = array(
			'settings' => array( self::THROTTLE_KEY_SET_NOTICE, 'Settings-change alerts throttled', '%d not emailed, see the Activity Log.' ),
			'login'    => array( self::THROTTLE_KEY_LOGIN_NOTE, 'Admin login alerts throttled', '%d not emailed, see the Activity Log.' ),
		);
		foreach ( $notices as $bucket => $notice ) {
			if ( empty( $dropped[ $bucket ] ) ) {
				continue;
			}
			$noticed = get_transient( $notice[0] );
			$noticed = is_array( $noticed ) ? $noticed : array();
			foreach ( $dropped[ $bucket ] as $blog => $lost ) {
				if ( in_array( $blog, $noticed, true ) ) {
					continue;
				}
				$noticed[] = $blog;
				$to        = array();
				foreach ( $lost as $event ) {
					$to = array_merge( $to, $event['recipients'] ?? array() );
				}
				$this->send_mail(
					array(
						array(
							'type'       => 'firewall',
							'title'      => $notice[1],
							'detail'     => sprintf( $notice[2], count( $lost ) ),
							'recipients' => array_values( array_unique( $to ) ),
						),
					),
					array_merge( $context, $lost[0]['ctx'] ?? array() )
				);
			}
			set_transient( $notice[0], $noticed, HOUR_IN_SECONDS );
		}
	}

	/**
	 * Mail a set of events. Events with their own recipients are not also sent to the usual ones.
	 *
	 * @param array<int, array<string, mixed>> $events  Events.
	 * @param array<string, string>            $context Mail context.
	 */
	private function send_mail( array $events, array $context ): void {
		$mail = AlertFormatter::format( $events, $context );
		$to   = array();
		foreach ( $events as $event ) {
			$to = array_merge( $to, ! empty( $event['recipients'] ) ? $event['recipients'] : $this->recipients() );
		}
		wp_mail( array_values( array_unique( $to ) ), $mail['subject'], $mail['body'] );
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
		$ok   = wp_mail( $this->recipients(), $mail['subject'], $mail['body'] );
		remove_action( 'wp_mail_failed', $capture );
		if ( $ok ) {
			return true;
		}
		return '' !== $error ? $error : __( 'WordPress could not send the email. Check your site\'s mail setup (an SMTP plugin is often needed).', 'wp-bouncer' );
	}

	/**
	 * Get the alert recipients.
	 *
	 * @return string[] Where alerts go.
	 */
	public function recipients(): array {
		return $this->base_recipients( null );
	}

	/**
	 * The configured recipients, or the site admin when none are set.
	 *
	 * @param array<string, mixed>|null $alerts Alert settings to read instead of the loaded ones.
	 * @return string[]
	 */
	private function base_recipients( ?array $alerts ): array {
		$list = (array) ( ( $alerts ?? $this->settings() )['recipients'] ?? array() );
		return ! empty( $list ) ? array_values( $list ) : array( (string) get_option( 'admin_email' ) );
	}

	/**
	 * Describe who, where and when.
	 *
	 * @return array<string, string> Who, where, when.
	 */
	private function context(): array {
		$user    = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		$actor   = $user && $user->exists() ? sprintf( '%s (user ID %d)', LoginEvent::clean_login( (string) $user->user_login ), $user->ID ) : 'no logged-in user (WP-CLI, a scheduled task, or code)';
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
	 * @param array{type: string, title: string, detail: string, log_detail?: string} $event   Event.
	 * @param array<string, string>                                                   $context Context.
	 */
	private function log( array $event, array $context ): void {
		$request = $this->plugin->current_request();
		$detail  = $event['log_detail'] ?? $event['detail'];
		$this->plugin->log_writer()->record(
			array(
				'ip'         => $context['ip'],
				'country'    => $context['country'],
				'rule'       => self::LOG_RULE,
				'action'     => BlockLogInterface::ACTION_ALERT,
				'reason'     => $event['title'] . ( '' !== $detail ? ' — ' . $detail : '' ) . ' — by ' . $context['actor'],
				'method'     => ( defined( 'WP_CLI' ) && WP_CLI ) ? 'CLI' : $request->method(),
				'uri'        => ( defined( 'WP_CLI' ) && WP_CLI ) ? '' : $request->uri(),
				'user_agent' => $context['user_agent'],
			)
		);
	}
}
