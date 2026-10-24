<?php
/**
 * Updates from GitHub releases through WordPress's normal plugin updater.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Update;

use WPBouncer\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * The plugin header declares "Update URI: https://github.com/jimhstew/wp-bouncer".
 * Because of that, WordPress (5.8+) never takes updates for this plugin from
 * WordPress.org, so an unrelated wordpress.org plugin with the same folder
 * name can't replace it. Instead WordPress asks the update_plugins_github.com
 * filter, which this class answers from the update.json file attached to the
 * latest GitHub release.
 *
 * From there everything is standard WordPress: the "new version available"
 * notice, Update now, bulk updates, the auto-update toggle and WP-CLI.
 *
 * Two safeguards are added:
 * - The zip must come from this repository's release downloads.
 * - Its SHA-256 must match the one in update.json, or the update is refused
 *   before WordPress touches the installed copy.
 *
 * The only data sent is a plain HTTPS GET with the User-Agent
 * "WP-Bouncer/<version>": no site URL and no visitor information.
 * Define WP_BOUNCER_DISABLE_UPDATES as true to switch the check off.
 */
final class Updater {

	/** GitHub owner/repository the releases come from. */
	public const REPOSITORY = 'jimhstew/wp-bouncer';

	/** Plugin slug (folder name). */
	public const SLUG = 'wp-bouncer';

	/** Cached manifest (or the last error). */
	public const CACHE = 'wp_bouncer_update_manifest';

	/** How long a good answer is cached. WordPress itself checks every 12 hours. */
	private const TTL = 6 * HOUR_IN_SECONDS;

	/** How long to wait before retrying after a failed check. */
	private const ERROR_TTL = HOUR_IN_SECONDS;

	/**
	 * Plugin file.
	 *
	 * @var string
	 */
	private string $plugin_file;

	/**
	 * Set up the Updater.
	 *
	 * @param string $plugin_file Absolute path of wp-bouncer.php.
	 */
	public function __construct( string $plugin_file ) {
		$this->plugin_file = $plugin_file;
	}

	/** True when WP_BOUNCER_DISABLE_UPDATES is defined as true. */
	public static function is_disabled(): bool {
		return defined( 'WP_BOUNCER_DISABLE_UPDATES' ) && WP_BOUNCER_DISABLE_UPDATES;
	}

	/** Hook into WordPress. */
	public function register(): void {
		$host = (string) wp_parse_url( self::repository_url(), PHP_URL_HOST );
		add_filter( "update_plugins_{$host}", array( $this, 'filter_update' ), 10, 3 );
		add_filter( 'plugins_api', array( $this, 'filter_plugin_info' ), 20, 3 );
		add_filter( 'upgrader_pre_download', array( $this, 'filter_pre_download' ), 10, 4 );
		add_action( 'upgrader_process_complete', array( $this, 'forget' ), 10, 0 );
		// "Check again" on Dashboard > Updates should really check again.
		add_action( 'load-update-core.php', array( $this, 'maybe_forget_on_force_check' ) );
	}

	/** URL of the GitHub repository, https://github.com/<owner>/<repo>. */
	public static function repository_url(): string {
		return 'https://github.com/' . self::REPOSITORY;
	}

	/** Where update.json is read from: always the latest (non-draft, non-prerelease) release. */
	public static function manifest_url(): string {
		$url = self::repository_url() . '/releases/latest/download/update.json';
		if ( ! self::source_filters_allowed() ) {
			return $url;
		}
		/**
		 * Filters the URL of the release manifest. For testing and forks.
		 *
		 * Only applied when WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS is true in wp-config.php.
		 *
		 * @param string $url Default https://github.com/<repo>/releases/latest/download/update.json.
		 */
		return (string) apply_filters( 'wp_bouncer_update_manifest_url', $url );
	}

	/** Every update zip must start with this URL. */
	public static function package_prefix(): string {
		$prefix = self::repository_url() . '/releases/download/';
		if ( ! self::source_filters_allowed() ) {
			return $prefix;
		}
		/**
		 * Filters where update zips may be downloaded from. For testing and forks.
		 *
		 * Only applied when WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS is true in wp-config.php.
		 *
		 * @param string $prefix Default https://github.com/<repo>/releases/download/.
		 */
		return (string) apply_filters( 'wp_bouncer_update_package_prefix', $prefix );
	}

	/**
	 * Are the update-source filters honoured?
	 *
	 * A plugin that can add a filter could otherwise redirect updates to its
	 * own server, so the filters only work when wp-config.php opts in.
	 */
	public static function source_filters_allowed(): bool {
		return SourcePolicy::filters_allowed( defined( 'WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS' ), defined( 'WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS' ) ? WP_BOUNCER_ALLOW_UPDATE_SOURCE_FILTERS : null );
	}

	/**
	 * The latest release, from cache or GitHub.
	 *
	 * @param bool $fresh Skip the cache.
	 */
	public function manifest( bool $fresh = false ): ?ReleaseManifest {
		$cached = $fresh ? false : get_site_transient( self::CACHE );
		if ( is_array( $cached ) && isset( $cached['json'] ) ) {
			return ReleaseManifest::from_json( (string) $cached['json'], self::package_prefix() );
		}
		if ( is_array( $cached ) && isset( $cached['error'] ) ) {
			return null;
		}

		$response = wp_safe_remote_get(
			self::manifest_url(),
			array(
				'timeout'     => 10,
				'redirection' => 5,
				'user-agent'  => 'WP-Bouncer/' . Plugin::VERSION,
				'headers'     => array( 'Accept' => 'application/json' ),
			)
		);
		$code     = (int) wp_remote_retrieve_response_code( $response );
		$body     = (string) wp_remote_retrieve_body( $response );
		$manifest = 200 === $code ? ReleaseManifest::from_json( $body, self::package_prefix() ) : null;

		if ( null === $manifest ) {
			$error = is_wp_error( $response ) ? $response->get_error_message() : ( 200 === $code ? 'invalid update.json' : 'HTTP ' . $code );
			set_site_transient( self::CACHE, array( 'error' => $error ), self::ERROR_TTL );
			return null;
		}
		set_site_transient( self::CACHE, array( 'json' => $body ), self::TTL );
		return $manifest;
	}

	/** Why the last check failed, or '' when it didn't. Shown on the Tools tab. */
	public static function last_error(): string {
		$cached = get_site_transient( self::CACHE );
		return is_array( $cached ) && isset( $cached['error'] ) ? (string) $cached['error'] : '';
	}

	/** Drop the cached answer so the next check asks GitHub. */
	public function forget(): void {
		delete_site_transient( self::CACHE );
	}

	/** Clear the cache when an admin clicks "Check again". */
	public function maybe_forget_on_force_check(): void {
		// phpcs:ignore WordPress.Security.NonceVerification -- core's own "Check again" link; it only clears a cache and is capability-checked.
		if ( ! empty( $_GET['force-check'] ) && current_user_can( 'update_plugins' ) ) {
			$this->forget();
		}
	}

	/** This plugin's file relative to the plugins folder: wp-bouncer/wp-bouncer.php. */
	private function basename(): string {
		return plugin_basename( $this->plugin_file );
	}

	/**
	 * Answer WordPress's update check for this plugin.
	 *
	 * Returning data even when there is no newer version matters: it puts the
	 * plugin in the "no update" list, which is what makes WordPress show the
	 * auto-update toggle for it.
	 *
	 * @param array<string, mixed>|false $update      Update data so far.
	 * @param array<string, mixed>       $plugin_data Plugin headers.
	 * @param string                     $plugin_file Plugin being checked.
	 * @return array<string, mixed>|false
	 */
	public function filter_update( $update, $plugin_data, $plugin_file ) {
		if ( $plugin_file !== $this->basename() ) {
			return $update; // Another plugin hosted on the same domain.
		}
		$manifest = $this->manifest();
		if ( null === $manifest ) {
			return $update;
		}
		global $wp_version;
		if ( ! $manifest->is_compatible( (string) $wp_version, PHP_VERSION ) ) {
			// Don't offer a release this site can't run. Reporting the installed
			// version keeps the plugin in the "no update" list (auto-update toggle).
			return array(
				'slug'         => self::SLUG,
				'version'      => Plugin::VERSION,
				'url'          => self::repository_url(),
				'package'      => '',
				'requires'     => $manifest->requires(),
				'requires_php' => $manifest->requires_php(),
				'tested'       => $manifest->tested(),
				'icons'        => array(),
			);
		}
		return array(
			'slug'         => self::SLUG,
			'version'      => $manifest->version(),
			'url'          => self::repository_url(),
			'package'      => $manifest->package(),
			'requires'     => $manifest->requires(),
			'requires_php' => $manifest->requires_php(),
			'tested'       => $manifest->tested(),
			'icons'        => array(),
		);
	}

	/**
	 * Fill the "View details" window.
	 *
	 * @param false|object|array<string, mixed> $result Result so far.
	 * @param string                            $action plugins_api action.
	 * @param object                            $args   Request arguments.
	 * @return false|object|array<string, mixed>
	 */
	public function filter_plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! is_object( $args ) || ( $args->slug ?? '' ) !== self::SLUG ) {
			return $result;
		}
		$manifest = $this->manifest();
		if ( null === $manifest ) {
			return $result;
		}
		return (object) array(
			'name'          => 'WP Bouncer',
			'slug'          => self::SLUG,
			'version'       => $manifest->version(),
			'author'        => '<a href="' . esc_url( self::repository_url() ) . '">WP Bouncer contributors</a>',
			'homepage'      => self::repository_url(),
			'requires'      => $manifest->requires(),
			'requires_php'  => $manifest->requires_php(),
			'tested'        => $manifest->tested(),
			'last_updated'  => $manifest->released(),
			'download_link' => $manifest->package(),
			'sections'      => array(
				'description' => '<p>' . esc_html__( 'A self-contained firewall that turns away unwanted visitors at the door: IP and country blocking, bad user-agents, brute-force login lockouts, XML-RPC blocking, rate limiting, user-enumeration protection and a lightweight WAF. No cloud service, no subscription.', 'wp-bouncer' ) . '</p>'
					. '<p><a href="' . esc_url( self::repository_url() ) . '">' . esc_html( self::repository_url() ) . '</a></p>',
				'changelog'   => '' !== $manifest->changelog() ? $manifest->changelog_html() : '<p><a href="' . esc_url( self::repository_url() . '/releases' ) . '">' . esc_html__( 'Release notes on GitHub', 'wp-bouncer' ) . '</a></p>',
			),
		);
	}

	/**
	 * Download our update zip ourselves and check its SHA-256.
	 *
	 * Runs for every update WordPress downloads; anything that isn't one of
	 * our release zips is left alone.
	 *
	 * @param false|string|\WP_Error $reply      Result so far.
	 * @param string                 $package    URL being downloaded.
	 * @param object                 $upgrader   WP_Upgrader instance.
	 * @param array<string, mixed>   $hook_extra Context.
	 * @return false|string|\WP_Error Path to the verified zip, an error, or $reply unchanged.
	 */
	public function filter_pre_download( $reply, $package, $upgrader, $hook_extra ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- fixed signature of the upgrader_pre_download filter.
		if ( false !== $reply || ! is_string( $package ) || 0 !== strpos( $package, self::package_prefix() ) ) {
			return $reply;
		}

		// The zip WordPress was told about must be the one in the newest manifest.
		$manifest = $this->manifest();
		if ( null === $manifest || $manifest->package() !== $package ) {
			$manifest = $this->manifest( true );
		}
		if ( null === $manifest || $manifest->package() !== $package ) {
			return new \WP_Error( 'wp_bouncer_update_changed', __( 'The WP Bouncer release information changed while updating. Go to Dashboard → Updates, click "Check again", and retry.', 'wp-bouncer' ) );
		}

		if ( isset( $upgrader->skin ) && is_object( $upgrader->skin ) && method_exists( $upgrader->skin, 'feedback' ) ) {
			$upgrader->skin->feedback( 'downloading_package', $package );
		}
		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$file = download_url( $package, 300 );
		if ( is_wp_error( $file ) ) {
			return $file;
		}

		$actual = (string) hash_file( 'sha256', $file );
		if ( ! hash_equals( $manifest->sha256(), $actual ) ) {
			wp_delete_file( $file );
			return new \WP_Error(
				'wp_bouncer_checksum',
				sprintf(
					/* translators: 1: expected SHA-256, 2: actual SHA-256. */
					__( 'The downloaded WP Bouncer update failed its integrity check, so it was not installed. Expected SHA-256 %1$s, got %2$s.', 'wp-bouncer' ),
					$manifest->sha256(),
					$actual
				)
			);
		}
		return $file;
	}
}
