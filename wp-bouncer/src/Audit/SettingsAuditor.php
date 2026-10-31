<?php
/**
 * Audits every write to the settings option, whoever makes it.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Audit;

use WPBouncer\Admin\AdminController;
use WPBouncer\Log\BlockLog;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Plugin;
use WPBouncer\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress adapter: collects context, writes the Activity Log row, queues the
 * alert, reloads settings and fires wp_bouncer_settings_changed.
 *
 * The register() method only adds hooks. Services are built lazily, on a real write.
 */
final class SettingsAuditor {

	/**
	 * Depth of as_upgrade() calls in progress.
	 *
	 * @var int
	 */
	private static int $upgrade_depth = 0;

	/**
	 * Raw option values seen just before a delete, keyed by blog id.
	 *
	 * @var array<int, mixed>
	 */
	private array $stash = array();

	/**
	 * The Plugin the hooks were registered for (register() is idempotent per Plugin).
	 *
	 * @var Plugin|null
	 */
	private static ?Plugin $registered_for = null;

	/**
	 * Plugin instance.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Set up the auditor.
	 *
	 * @param Plugin $plugin Plugin.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/** Hook into the options API. No reads, no queries. */
	public function register(): void {
		if ( self::$registered_for === $this->plugin ) {
			return;
		}
		// A new Plugin instance takes over: drop the old instance's hooks first so nothing is audited twice.
		self::remove_hooks();
		self::$registered_for = $this->plugin;
		add_action( 'update_option_' . Settings::OPTION, array( $this, 'on_update' ), 10, 2 );
		add_action( 'add_option_' . Settings::OPTION, array( $this, 'on_add' ), 10, 2 );
		add_action( 'delete_option', array( $this, 'before_delete' ), 10, 1 );
		add_action( 'delete_option_' . Settings::OPTION, array( $this, 'on_delete' ), 10, 0 );
	}

	/**
	 * Remove every auditor hook for uninstall, which must not write rows into tables it just dropped.
	 *
	 * Does nothing outside an uninstall (WP_UNINSTALL_PLUGIN defined).
	 *
	 * @internal Only for uninstall.php.
	 */
	public static function unregister(): void {
		if ( defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			self::remove_hooks();
		}
	}

	/** Remove the callbacks of every auditor instance from the option hooks. */
	private static function remove_hooks(): void {
		global $wp_filter;
		$tags = array( 'update_option_' . Settings::OPTION, 'add_option_' . Settings::OPTION, 'delete_option', 'delete_option_' . Settings::OPTION );
		foreach ( $tags as $tag ) {
			if ( ! isset( $wp_filter[ $tag ] ) ) {
				continue;
			}
			foreach ( $wp_filter[ $tag ]->callbacks as $priority => $callbacks ) {
				foreach ( $callbacks as $callback ) {
					$fn = $callback['function'];
					if ( is_array( $fn ) && $fn[0] instanceof self ) {
						remove_action( $tag, $fn, $priority );
					}
				}
			}
		}
		self::$registered_for = null;
	}

	/**
	 * Run a callable whose settings writes are labelled "upgrade" in the audit.
	 *
	 * @internal Only for the plugin's own migrations.
	 *
	 * @param callable $callback Work to run.
	 * @return mixed What the callback returned.
	 */
	public static function as_upgrade( callable $callback ): mixed {
		++self::$upgrade_depth;
		try {
			return $callback();
		} finally {
			--self::$upgrade_depth;
		}
	}

	/**
	 * The option was updated.
	 *
	 * @param mixed $before Old raw value.
	 * @param mixed $after  New raw value.
	 */
	public function on_update( $before, $after ): void {
		$this->on_write( $before, $after );
	}

	/**
	 * The option was added (also what update_option() does for a missing option).
	 *
	 * @param string $option Option name (always ours; the hook passes it first).
	 * @param mixed  $value  New raw value.
	 */
	public function on_add( $option, $value ): void {
		$this->on_write( Settings::defaults(), $value, false, false );
	}

	/**
	 * Any option is about to be deleted: remember ours.
	 *
	 * @param string $option Option name.
	 */
	public function before_delete( $option ): void {
		if ( Settings::OPTION === $option ) {
			$this->stash[ get_current_blog_id() ] = get_option( Settings::OPTION );
		}
	}

	/** The option was deleted. */
	public function on_delete(): void {
		$blog = get_current_blog_id();
		$old  = $this->stash[ $blog ] ?? array();
		unset( $this->stash[ $blog ] );
		$this->on_write( $old, Settings::defaults(), true, true );
	}

	/**
	 * Audit one write.
	 *
	 * The drift monitor brackets the work: it compares the old value with the stored fingerprint first
	 * (a change made outside the plugin is reported before this write's own row) and stores the
	 * fingerprint of the new value last.
	 *
	 * @param mixed $old_raw     Old raw value.
	 * @param mixed $new_raw     New raw value.
	 * @param bool  $deleted     Option was deleted.
	 * @param bool  $old_present True when the option was there before (false for an add).
	 */
	private function on_write( $old_raw, $new_raw, bool $deleted = false, bool $old_present = true ): void {
		$monitor = $this->plugin->drift_monitor();
		$monitor->before_audited_write( $old_raw, $old_present );
		try {
			$change = SettingsChange::from( $old_raw, $new_raw, $deleted );
			if ( null === $change ) {
				return; // No change to audit; the finally block below still runs after_audited_write().
			}
			$actor       = $this->actor();
			$row_written = $this->record_row( $change->reason( $actor ) );

			if ( ! empty( $change->risky ) ) {
				$this->plugin->alerts()->on_risky_settings_change( $change->risky, $change->changes, $change->new, $change->old, $actor, $row_written );
			}
		} finally {
			$monitor->after_audited_write( $new_raw, ! $deleted );
		}

		// The in-memory copy belongs to the original blog.
		if ( ! $this->switched() ) {
			$this->plugin->reload_settings();
		}

		/**
		 * Fires once per real settings change, from every source (admin screen, WP-CLI, code).
		 *
		 * $old and $new hold setting values (normalised). Listeners must not log them. After a change
		 * made outside WP Bouncer is found, it fires with an empty $old and the actor "unknown".
		 *
		 * @param string[]             $changes Changed key paths, such as "rules.xmlrpc.enabled" (lists count as one path).
		 * @param array<string, mixed> $old     Settings before.
		 * @param array<string, mixed> $new     Settings after.
		 * @param string               $actor   Who did it, such as "jim", "jim (cli)" or "unknown".
		 */
		do_action( 'wp_bouncer_settings_changed', $change->changes, $change->old, $change->new, $actor );
	}

	/**
	 * Write one audit row (alert action, rule "settings") for the current request.
	 *
	 * @param string $reason          What happened and who did it; no setting values.
	 * @param bool   $request_details Store the request's IP, country, method, URI and user agent. Drift rows pass false:
	 *                                the request belongs to whoever ran the check, not to the author of the change.
	 * @return bool False when the row could not be written (for example the table is missing).
	 */
	public function record_row( string $reason, bool $request_details = true ): bool {
		$fields = array(
			'ip'         => '',
			'country'    => '',
			'rule'       => AdminController::SETTINGS_LOG_RULE,
			'action'     => BlockLogInterface::ACTION_ALERT,
			'reason'     => mb_strimwidth( $reason, 0, 255, '...' ),
			'method'     => '',
			'uri'        => '',
			'user_agent' => '',
		);
		if ( $request_details ) {
			$request              = $this->plugin->current_request();
			$ip                   = $request->ip();
			$fields['ip']         = $ip;
			$fields['country']    = '' !== $ip ? (string) $this->plugin->geo()->lookup( $ip ) : '';
			$fields['method']     = $request->method();
			$fields['uri']        = $request->uri();
			$fields['user_agent'] = $request->user_agent();
		}
		if ( $this->switched() ) {
			// The cached writer is bound to the original blog's table prefix.
			global $wpdb;
			$writer = new BlockLog( $wpdb );
		} else {
			$writer = $this->plugin->log_writer();
		}
		return $writer->record( $fields ) > 0;
	}

	/**
	 * Who is acting, for audit rows.
	 *
	 * @return string Never empty.
	 */
	public function actor(): string {
		$login = null;
		$id    = 0;
		if ( function_exists( 'wp_get_current_user' ) ) {
			$user = wp_get_current_user();
			if ( $user->exists() ) {
				$login = (string) $user->user_login;
				$id    = (int) $user->ID;
			}
		}
		return AuditActor::resolve(
			$login,
			array(
				'upgrade' => self::$upgrade_depth > 0,
				'cli'     => defined( 'WP_CLI' ) && WP_CLI,
				'cron'    => function_exists( 'wp_doing_cron' ) && wp_doing_cron(),
				'rest'    => defined( 'REST_REQUEST' ) && REST_REQUEST,
				'ajax'    => function_exists( 'wp_doing_ajax' ) && wp_doing_ajax(),
			),
			$id
		);
	}

	/** Is another blog's context active (multisite switch_to_blog)? */
	private function switched(): bool {
		return function_exists( 'ms_is_switched' ) && ms_is_switched();
	}
}
