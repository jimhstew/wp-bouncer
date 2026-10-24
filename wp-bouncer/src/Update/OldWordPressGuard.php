<?php
/**
 * What the plugin does on a WordPress older than its minimum.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Update;

defined( 'ABSPATH' ) || exit;

/**
 * Used by wp-bouncer.php when PHP is new enough but WordPress is not.
 *
 * Versions before 1.2.0 let core's automatic updater install a release that
 * requires a newer WordPress (core only enforces Requires PHP there). Such a
 * site gets no firewall. Rather than stay silent and stuck, the plugin:
 * - keeps the Updater registered, so a fixed release can still arrive;
 * - shows a clear admin notice;
 * - emails the site admin (and the network admin) once that the firewall is OFF.
 *
 * Everything here uses functions available since WordPress 5.8, the first
 * release with the update_plugins_{hostname} filter the Updater relies on.
 */
final class OldWordPressGuard {

	/** Site option set once the email was sent; cleared when WordPress is new enough again. */
	public const FLAG_OPTION = 'wp_bouncer_old_wp_mailed';

	/** Single cron event that sends the email when nobody opens the admin. */
	public const CRON_HOOK = 'wp_bouncer_old_wp_email';

	/**
	 * Plugin file.
	 *
	 * @var string
	 */
	private string $plugin_file;

	/**
	 * WordPress version in use.
	 *
	 * @var string
	 */
	private string $wp_version;

	/**
	 * Minimum WordPress version.
	 *
	 * @var string
	 */
	private string $min_wp;

	/**
	 * Set up the guard.
	 *
	 * @param string $plugin_file Absolute path of wp-bouncer.php.
	 * @param string $wp_version  WordPress version in use (a seam for tests).
	 * @param string $min_wp      Minimum WordPress version.
	 */
	public function __construct( string $plugin_file, string $wp_version, string $min_wp ) {
		$this->plugin_file = $plugin_file;
		$this->wp_version  = $wp_version;
		$this->min_wp      = $min_wp;
	}

	/** Hook everything up. Cheap: two cached option reads per request. */
	public function register(): void {
		if ( ! Updater::is_disabled() ) {
			( new Updater( $this->plugin_file ) )->register();
		}
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
		add_action( 'network_admin_notices', array( $this, 'render_notice' ) );
		add_action( 'admin_init', array( $this, 'maybe_email' ) );
		add_action( self::CRON_HOOK, array( $this, 'maybe_email' ) );
		if ( false === get_site_option( self::FLAG_OPTION ) && ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_single_event( time() + MINUTE_IN_SECONDS, self::CRON_HOOK );
		}
	}

	/** Forget that the email went out, so a later recurrence is reported again. Runs when WordPress is new enough. */
	public static function reset(): void {
		if ( false !== get_site_option( self::FLAG_OPTION ) ) {
			delete_site_option( self::FLAG_OPTION );
		}
	}

	/** The one-sentence explanation used by the notice and the email. */
	public function message(): string {
		return sprintf(
			/* translators: 1: required WordPress version, 2: installed WordPress version. */
			__( 'WP Bouncer is not running: the firewall is OFF. It needs WordPress %1$s or newer, and this site runs WordPress %2$s. Update WordPress to protect the site again.', 'wp-bouncer' ),
			$this->min_wp,
			$this->wp_version
		);
	}

	/** Show the explanation to people who can manage plugins. */
	public function render_notice(): void {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		printf( '<div class="notice notice-error"><p>%s</p></div>', esc_html( $this->message() ) );
	}

	/**
	 * Email the site admin (and the network admin) once.
	 *
	 * The flag is claimed with add_site_option(), which is atomic, so two
	 * requests cannot both send it.
	 */
	public function maybe_email(): void {
		if ( add_site_option( self::FLAG_OPTION, (string) time() ) ) {
			$this->send();
		}
	}

	/** Build and send the email. */
	private function send(): void {
		$to = array( (string) get_option( 'admin_email' ) );
		if ( is_multisite() ) {
			$to[] = (string) get_site_option( 'admin_email' );
		}
		$to = array_values( array_unique( array_filter( $to, 'is_email' ) ) );
		if ( ! $to ) {
			return;
		}

		$site    = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$subject = sprintf(
			/* translators: %s: site name. */
			__( '[%s] WP Bouncer firewall is OFF', 'wp-bouncer' ),
			$site
		);
		$body = $this->message() . "\n\n" . sprintf(
			/* translators: %s: URL of the WordPress updates screen. */
			__( 'Update WordPress here: %s', 'wp-bouncer' ),
			self_admin_url( 'update-core.php' )
		) . "\n";
		wp_mail( $to, $subject, $body );
	}
}
