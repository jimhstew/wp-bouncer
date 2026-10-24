<?php
/**
 * The WP Bouncer box on the WordPress Dashboard.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Installer;
use WPBouncer\Plugin;
use WPBouncer\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress-facing adapter: registers the widget for administrators, caches
 * the aggregate numbers (WidgetStats builds them) and renders them.
 *
 * The widget is per site: on multisite each site's dashboard shows its own
 * log, and nothing is added to the network dashboard.
 */
final class DashboardWidget {

	public const WIDGET_ID = 'wp_bouncer_dashboard';

	/** Transient holding the aggregate array (starts with wpb_, so uninstall sweeps it). */
	public const TRANSIENT = 'wpb_widget_stats';

	/** Longer-lived copy of the numbers, served while another request rebuilds them. */
	public const STALE_TRANSIENT = 'wpb_widget_stats_stale';

	/** Short-lived marker: a request is rebuilding the numbers. */
	public const LOCK_TRANSIENT = 'wpb_widget_stats_lock';

	/** Rows in the 14-day window above which the numbers are cached for the longest allowed time. */
	public const FLOOD_ROWS = 100000;

	/** Longest the lock is held, in seconds, if the build never finishes. */
	private const LOCK_SECONDS = 30;

	/**
	 * Plugin instance.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Clock.
	 *
	 * @var Clock
	 */
	private Clock $clock;

	/**
	 * Does the emergency switch count as on? (A seam for tests; the constant cannot be undefined.)
	 *
	 * @var callable
	 */
	private $is_disabled;

	/**
	 * Set up the widget.
	 *
	 * @param Plugin        $plugin   Plugin instance.
	 * @param Clock|null    $clock    Clock (tests pass a frozen one).
	 * @param callable|null $disabled Returns true when WP_BOUNCER_DISABLE counts as set (default: the constant).
	 */
	public function __construct( Plugin $plugin, ?Clock $clock = null, ?callable $disabled = null ) {
		$this->plugin      = $plugin;
		$this->clock       = $clock ?? new Clock();
		$this->is_disabled = $disabled ?? array( Plugin::class, 'is_disabled' );
	}

	/** Register the hooks. */
	public function register(): void {
		add_action( 'wp_dashboard_setup', array( $this, 'add_widget' ) );
		// Anything that changes what the numbers say throws the cache away.
		add_action( 'wp_bouncer_log_cleared', array( self::class, 'flush' ) );
		add_action( 'wp_bouncer_settings_changed', array( self::class, 'flush' ) );
		// After Plugin::daily_maintenance() (priority 10) has purged the log.
		add_action( Installer::CRON_HOOK, array( self::class, 'flush' ), 20 );
	}

	/**
	 * Forget the cached numbers (and the stale copy, which would show deleted rows).
	 *
	 * Any future code that deletes log rows must call this, as the clear-log handler, the daily purge
	 * and the settings hooks do.
	 */
	public static function flush(): void {
		delete_transient( self::TRANSIENT );
		delete_transient( self::STALE_TRANSIENT );
	}

	/** Add the widget for users who may manage the plugin. */
	public function add_widget(): void {
		if ( is_network_admin() || ! current_user_can( AdminController::CAPABILITY ) ) {
			return;
		}
		wp_add_dashboard_widget(
			self::WIDGET_ID,
			esc_html__( 'WP Bouncer', 'wp-bouncer' ),
			array( $this, 'render' )
		);
	}

	/** Print the widget body. */
	public function render(): void {
		if ( ! current_user_can( AdminController::CAPABILITY ) ) {
			return;
		}
		$data = $this->data();
		// The same counting as the Dashboard tab (RuleStatus), over the built-in rules. RuleOverview is
		// deliberately not memoised (it must reflect settings saved earlier in the request); this reads
		// only settings and three options, and the widget renders once per page.
		$totals      = ( new RuleOverview( $this->plugin ) )->totals();
		$rules_on    = $totals['on'];
		$rules_total = $totals['total'];
		$now         = $this->clock->now();
		require __DIR__ . '/views/widget.php';
	}

	/**
	 * The aggregate numbers, from the transient when it is fresh.
	 *
	 * While one request rebuilds them, others get the stale copy if there is one. With no stale copy
	 * they build too: a slow page is better than an empty widget.
	 *
	 * @return array<string, mixed>
	 */
	public function data(): array {
		$mode     = $this->plugin->settings()->is_monitor_mode() ? 'monitor' : 'enforce';
		$disabled = (bool) call_user_func( $this->is_disabled );
		$geo      = $this->plugin->geo_database_loaded();
		$sig      = $mode . '|' . ( $disabled ? '1' : '0' ) . '|' . ( $geo ? '1' : '0' );

		$cached = self::read( self::TRANSIENT, $sig );
		if ( null !== $cached ) {
			return $cached;
		}
		if ( false !== get_transient( self::LOCK_TRANSIENT ) ) {
			$stale = self::read( self::STALE_TRANSIENT, $sig );
			if ( null !== $stale ) {
				return $stale;
			}
		}

		set_transient( self::LOCK_TRANSIENT, 1, self::LOCK_SECONDS );
		try {
			$data = ( new WidgetStats() )->build( $this->plugin->log(), $this->clock, $mode, $disabled, $geo );
			/**
			 * Filters how long the dashboard widget's numbers are cached, in seconds (60 to 3600).
			 * A very large log (see DashboardWidget::FLOOD_ROWS in the last 14 days) is always cached for 3600.
			 *
			 * @param int $seconds Default 300.
			 */
			$ttl = (int) apply_filters( 'wp_bouncer_widget_cache_ttl', 5 * MINUTE_IN_SECONDS );
			$ttl = (int) $data['window_total'] > self::FLOOD_ROWS ? HOUR_IN_SECONDS : max( 60, min( HOUR_IN_SECONDS, $ttl ) );
			$box = array(
				'sig'  => $sig,
				'data' => $data,
			);
			set_transient( self::TRANSIENT, $box, $ttl );
			set_transient( self::STALE_TRANSIENT, $box, DAY_IN_SECONDS );
		} finally {
			delete_transient( self::LOCK_TRANSIENT );
		}
		return $data;
	}

	/**
	 * Read a cached box if it is intact and was built for the same status.
	 *
	 * @param string $name Transient name.
	 * @param string $sig  Status signature.
	 * @return array<string, mixed>|null
	 */
	private static function read( string $name, string $sig ): ?array {
		$box = get_transient( $name );
		if ( is_array( $box ) && ( $box['sig'] ?? null ) === $sig && is_array( $box['data'] ?? null ) ) {
			return $box['data'];
		}
		return null;
	}

	/**
	 * Words for a trend, readable without colour or the arrow.
	 *
	 * @param string $trend  up|down|same|new.
	 * @param int    $now    Count in this period.
	 * @param int    $before Count in the previous period.
	 * @param bool   $day    True for 24 hours, false for 7 days.
	 */
	public static function trend_text( string $trend, int $now, int $before, bool $day ): string {
		$n    = abs( $now - $before );
		$diff = number_format_i18n( $n );
		switch ( $trend ) {
			case 'up':
				return $day
					/* translators: %s: how many more than in the previous 24 hours. */
					? sprintf( __( 'Up %s from the previous 24 hours', 'wp-bouncer' ), $diff )
					/* translators: %s: how many more than in the previous 7 days. */
					: sprintf( __( 'Up %s from the previous 7 days', 'wp-bouncer' ), $diff );
			case 'down':
				return $day
					/* translators: %s: how many fewer than in the previous 24 hours. */
					? sprintf( __( 'Down %s from the previous 24 hours', 'wp-bouncer' ), $diff )
					/* translators: %s: how many fewer than in the previous 7 days. */
					: sprintf( __( 'Down %s from the previous 7 days', 'wp-bouncer' ), $diff );
			case 'new':
				return $day
					? __( 'New: none in the previous 24 hours', 'wp-bouncer' )
					: __( 'New: none in the previous 7 days', 'wp-bouncer' );
			default:
				return $day
					? __( 'Same as the previous 24 hours', 'wp-bouncer' )
					: __( 'Same as the previous 7 days', 'wp-bouncer' );
		}
	}

	/**
	 * Arrow for a trend (decoration only; the words carry the meaning).
	 *
	 * @param string $trend up|down|same|new.
	 */
	public static function trend_arrow( string $trend ): string {
		switch ( $trend ) {
			case 'up':
			case 'new':
				return "\u{25B2}";
			case 'down':
				return "\u{25BC}";
			default:
				return "\u{25AC}";
		}
	}
}
