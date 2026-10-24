<?php
/**
 * Writes one traffic log row at the end of every request.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Traffic;

use WPBouncer\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Settings (settings['traffic']):
 * - enabled (bool): off by default, since it adds one database write per request.
 * - retention_days (int 1-7)
 * - skip_admins (bool): don't record logged-in administrators.
 * - skip_background (bool): don't record WordPress's own background requests
 *   (WP-Cron and the admin Heartbeat), which arrive every minute or so.
 *
 * The row is written on "shutdown", once the response code is final. That
 * includes requests the firewall refused, since its block page ends with
 * exit, which still runs shutdown hooks. Requests for files the web server
 * serves itself (images, CSS, JS) never reach WordPress and aren't recorded;
 * the server's own access log has those.
 *
 * Like alerts, this keeps running while WP_BOUNCER_DISABLE is on: it refuses nobody.
 */
final class TrafficRecorder {

	/** Hourly cron hook that removes old rows. */
	public const PURGE_HOOK = 'wp_bouncer_traffic_purge';

	/**
	 * Plugin instance.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Set up the TrafficRecorder.
	 *
	 * @param Plugin $plugin Plugin.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/** Hook into WordPress. */
	public function register(): void {
		add_action( self::PURGE_HOOK, array( $this, 'purge' ) );
		if ( ! empty( $this->settings()['enabled'] ) && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			// Late, after other shutdown work (such as alert emails) is done.
			add_action( 'shutdown', array( $this, 'record' ), 100 );
		}
	}

	/**
	 * Get this component's settings.
	 *
	 * @return array<string, mixed>
	 */
	private function settings(): array {
		$s = $this->plugin->settings()->get( 'traffic' );
		return is_array( $s ) ? $s : array();
	}

	/** Record the current request. */
	public function record(): void {
		try {
			$s       = $this->settings();
			$request = $this->plugin->current_request();
			if ( ! empty( $s['skip_background'] ) && self::is_background( $request->path(), $request->post() ) ) {
				return;
			}
			if ( ! empty( $s['skip_admins'] ) && $request->is_trusted() ) {
				return;
			}
			$status = http_response_code();
			$this->plugin->traffic_log()->record(
				array(
					'ip'         => $request->ip(),
					'method'     => $request->method(),
					'uri'        => $request->uri(),
					'status'     => false === $status ? 0 : (int) $status,
					'referrer'   => $request->header( 'Referer' ),
					'user_agent' => $request->user_agent(),
					'user_id'    => function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0,
				)
			);
		} catch ( \Throwable $e ) {
			// Logging must never break a page.
			return;
		}
	}

	/**
	 * Is this one of WordPress's own background requests?
	 *
	 * @param string               $path Normalised path.
	 * @param array<string, mixed> $post POST fields.
	 */
	public static function is_background( string $path, array $post ): bool {
		if ( '/wp-cron.php' === $path ) {
			return true;
		}
		return '/wp-admin/admin-ajax.php' === $path && 'heartbeat' === ( $post['action'] ?? '' );
	}

	/** Remove rows past the retention period (hourly cron). */
	public function purge(): void {
		$this->plugin->traffic_log()->purge_older_than( (int) ( $this->settings()['retention_days'] ?? TrafficLog::MAX_DAYS ) );
	}
}
