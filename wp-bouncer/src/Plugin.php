<?php
/**
 * Composition root: builds the services and connects them to WordPress hooks.
 *
 * @package WPBouncer
 */

namespace WPBouncer;

use WPBouncer\Admin\AdminController;
use WPBouncer\Alerts\AlertNotifier;
use WPBouncer\Firewall\Firewall;
use WPBouncer\Firewall\HttpResponder;
use WPBouncer\Firewall\IpResolver;
use WPBouncer\Firewall\Request;
use WPBouncer\Geo\ChainGeoProvider;
use WPBouncer\Geo\GeoDatabase;
use WPBouncer\Geo\GeoImport;
use WPBouncer\Geo\GeoProviderInterface;
use WPBouncer\Geo\HeaderGeoProvider;
use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Log\BlockLog;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Login\LoginGuard;
use WPBouncer\Rules\CountryRule;
use WPBouncer\Rules\IpBlocklistRule;
use WPBouncer\Rules\LoginLockoutRule;
use WPBouncer\Rules\NotFoundFloodRule;
use WPBouncer\Rules\RateLimitRule;
use WPBouncer\Rules\RuleInterface;
use WPBouncer\Rules\SensitiveFileRule;
use WPBouncer\Rules\UserAgentRule;
use WPBouncer\Rules\UserEnumerationRule;
use WPBouncer\Rules\WafRule;
use WPBouncer\Rules\XmlRpcRule;
use WPBouncer\Storage\CounterStoreInterface;
use WPBouncer\Storage\TransientStore;
use WPBouncer\Support\IpUtils;
use WPBouncer\Traffic\TrafficLog;
use WPBouncer\Traffic\TrafficRecorder;
use WPBouncer\Update\Updater;

defined( 'ABSPATH' ) || exit;

/**
 * The only class that knows how everything fits together. Every other class
 * receives its collaborators through its constructor.
 *
 * Timing: the firewall runs on plugins_loaded (priority 1). That is the
 * earliest point where pluggable functions such as is_user_logged_in() exist,
 * and it comes before themes, most plugin logic and all page rendering.
 */
final class Plugin {

	public const VERSION = '1.1.1';

	/** Option holding metadata about the imported geo database. */
	public const GEO_META_OPTION = 'wp_bouncer_geo_meta';

	private static ?Plugin $instance = null;

	private string $file;
	private Settings $settings;

	private ?CounterStoreInterface $store = null;
	private ?BlockLog $log                = null;
	private ?GeoProviderInterface $geo    = null;
	private ?GeoDatabase $geo_db          = null;
	private ?LoginGuard $guard            = null;
	private ?Request $request             = null;
	private ?string $client_ip            = null;
	private ?UploadsGuard $uploads        = null;
	private ?AlertNotifier $alerts        = null;
	private ?TrafficLog $traffic          = null;

	/**
	 * @param string $file Main plugin file.
	 */
	private function __construct( string $file ) {
		$this->file     = $file;
		$this->settings = Settings::load();
	}

	/**
	 * Create the singleton and register hooks. Safe to call more than once.
	 *
	 * @param string $file Main plugin file.
	 */
	public static function boot( string $file ): self {
		if ( null === self::$instance ) {
			self::$instance = new self( $file );
			self::$instance->register();
		}
		return self::$instance;
	}

	/** The booted instance, if any. */
	public static function instance(): ?self {
		return self::$instance;
	}

	/** Register every WordPress hook. */
	private function register(): void {
		register_activation_hook( $this->file, array( Installer::class, 'activate' ) );
		register_deactivation_hook( $this->file, array( Installer::class, 'deactivate' ) );

		add_action( 'plugins_loaded', array( Installer::class, 'maybe_upgrade' ), 0 );
		add_action( 'init', array( $this, 'load_textdomain' ) );
		add_action( Installer::CRON_HOOK, array( $this, 'daily_maintenance' ) );

		// The emergency switch turns off everything that can refuse a visitor,
		// including login lockouts, but keeps the admin screens so the settings
		// can be fixed.
		if ( ! self::is_disabled() ) {
			add_action( 'plugins_loaded', array( $this, 'run_firewall' ), 1 );
			$this->register_login_hooks();
			$this->register_xmlrpc_hooks();
			$this->register_user_enumeration_hooks();
			// Late, so other plugins have had their chance to turn a 404 into a page.
			add_action( 'template_redirect', array( $this, 'track_not_found' ), 999 );
		}

		// Not affected by WP_BOUNCER_DISABLE in the same way: the uploads guard
		// removes its .htaccess block while the switch is on, and alerts and the
		// traffic log keep working because they never refuse anyone.
		$this->uploads_guard()->register();
		$this->alerts()->register();
		( new TrafficRecorder( $this ) )->register();

		// Updates are not affected by WP_BOUNCER_DISABLE: updating is one way out of a bad version.
		if ( ! Updater::is_disabled() ) {
			( new Updater( $this->file ) )->register();
		}

		if ( is_admin() ) {
			( new AdminController( $this ) )->register();
		}
	}

	/** True when wp-config.php defines WP_BOUNCER_DISABLE as true. */
	public static function is_disabled(): bool {
		return defined( 'WP_BOUNCER_DISABLE' ) && WP_BOUNCER_DISABLE;
	}

	/** Load translations. */
	public function load_textdomain(): void {
		load_plugin_textdomain( 'wp-bouncer', false, dirname( plugin_basename( $this->file ) ) . '/languages' );
	}

	/* ------------------------------------------------------------------
	 * Services (built lazily)
	 * ---------------------------------------------------------------- */

	/** Current settings. */
	public function settings(): Settings {
		return $this->settings;
	}

	/** Re-read settings after the admin saves them. */
	public function reload_settings(): void {
		$this->settings = Settings::load();
		$this->guard    = null;
		$this->geo      = null;
	}

	/** Main plugin file path. */
	public function file(): string {
		return $this->file;
	}

	/** Expiring key/value store for counters and bans. */
	public function store(): CounterStoreInterface {
		if ( null === $this->store ) {
			$this->store = new TransientStore();
		}
		return $this->store;
	}

	/** Block log. */
	public function log(): BlockLog {
		if ( null === $this->log ) {
			global $wpdb;
			$this->log = new BlockLog( $wpdb );
		}
		return $this->log;
	}

	/** Traffic log (every request that reached WordPress). */
	public function traffic_log(): TrafficLog {
		if ( null === $this->traffic ) {
			global $wpdb;
			$this->traffic = new TrafficLog( $wpdb );
		}
		return $this->traffic;
	}

	/** Local geo database table. */
	public function geo_database(): GeoDatabase {
		if ( null === $this->geo_db ) {
			global $wpdb;
			$this->geo_db = new GeoDatabase( $wpdb );
		}
		return $this->geo_db;
	}

	/** Multi-request importer for the geo database (used by the Tools screen). */
	public function geo_import(): GeoImport {
		return new GeoImport( $this->geo_database() );
	}

	/**
	 * Country lookup chain according to settings.
	 *
	 * "header" mode trusts the configured header first and falls back to the
	 * local database. "database" mode uses only the local database.
	 */
	public function geo(): GeoProviderInterface {
		if ( null === $this->geo ) {
			$providers = array();
			if ( 'header' === $this->settings->get( 'geo_source' ) ) {
				$providers[] = new HeaderGeoProvider( wp_unslash( $_SERVER ), (string) $this->settings->get( 'geo_header' ), $this->client_ip() );
			}
			$meta = get_option( self::GEO_META_OPTION, array() );
			if ( ! empty( $meta['rows'] ) ) {
				$providers[] = $this->geo_database();
			}
			$this->geo = new ChainGeoProvider( $providers );
		}
		return $this->geo;
	}

	/** Keeps PHP from running in the uploads folder. */
	public function uploads_guard(): UploadsGuard {
		if ( null === $this->uploads ) {
			$this->uploads = new UploadsGuard( $this );
		}
		return $this->uploads;
	}

	/** Emails about new administrators and plugin changes. */
	public function alerts(): AlertNotifier {
		if ( null === $this->alerts ) {
			$this->alerts = new AlertNotifier( $this );
		}
		return $this->alerts;
	}

	/** Brute-force tracker. */
	public function login_guard(): LoginGuard {
		if ( null === $this->guard ) {
			$this->guard = new LoginGuard( $this->settings->rule( LoginGuard::RULE_ID ), $this->store(), $this->log() );
		}
		return $this->guard;
	}

	/** Resolved client IP for this request. */
	public function client_ip(): string {
		if ( null === $this->client_ip ) {
			$resolver        = new IpResolver( (string) $this->settings->get( 'ip_source' ), (array) $this->settings->get( 'trusted_proxies' ) );
			$this->client_ip = $resolver->resolve( wp_unslash( $_SERVER ) );
		}
		return $this->client_ip;
	}

	/** Is the current client on the allowlist (or loopback)? */
	public function client_is_allowlisted(): bool {
		$ip = $this->client_ip();
		return '' !== $ip && ( IpUtils::is_loopback( $ip ) || IpUtils::matches_any( $ip, (array) $this->settings->get( 'allowlist' ) ) );
	}

	/** Snapshot of the current request. */
	public function current_request(): Request {
		if ( null === $this->request ) {
			// WordPress adds slashes to all superglobals early (wp_magic_quotes), so strip them.
			$this->request = Request::from_globals(
				$this->client_ip(),
				wp_unslash( $_SERVER ),
				wp_unslash( $_GET ),  // phpcs:ignore WordPress.Security.NonceVerification
				wp_unslash( $_POST ), // phpcs:ignore WordPress.Security.NonceVerification
				static function (): bool {
					return function_exists( 'is_user_logged_in' ) && is_user_logged_in();
				},
				static function (): bool {
					return function_exists( 'current_user_can' ) && current_user_can( 'manage_options' );
				}
			);
		}
		return $this->request;
	}

	/**
	 * Build the rule chain in evaluation order: cheap checks first, regex-heavy ones last.
	 *
	 * Extend it with the "wp_bouncer_rules" filter (see docs/adding-a-rule.md).
	 *
	 * @return RuleInterface[]
	 */
	public function build_rules(): array {
		$s = $this->settings;

		$rules = array(
			new IpBlocklistRule( $s->rule( IpBlocklistRule::ID ) ),
			new SensitiveFileRule( $s->rule( SensitiveFileRule::ID ), $this->store() ),
			new NotFoundFloodRule( $s->rule( NotFoundFloodRule::ID ), $this->store() ),
			new LoginLockoutRule( $s->rule( LoginLockoutRule::ID ), $this->login_guard() ),
			new RateLimitRule( $s->rule( RateLimitRule::ID ), $this->store() ),
			new UserAgentRule( $s->rule( UserAgentRule::ID ) ),
			new XmlRpcRule( $s->rule( XmlRpcRule::ID ) ),
			new UserEnumerationRule( $s->rule( UserEnumerationRule::ID ) ),
			new CountryRule( $s->rule( CountryRule::ID ), $this->geo() ),
			new WafRule( $s->rule( WafRule::ID ) ),
		);

		/**
		 * Filter the firewall's rule chain.
		 *
		 * @param RuleInterface[] $rules  Rules in evaluation order.
		 * @param Plugin          $plugin Plugin instance.
		 */
		$rules = apply_filters( 'wp_bouncer_rules', $rules, $this );

		return array_values(
			array_filter(
				(array) $rules,
				static function ( $rule ) {
					return $rule instanceof RuleInterface;
				}
			)
		);
	}

	/* ------------------------------------------------------------------
	 * Hook callbacks
	 * ---------------------------------------------------------------- */

	/** Run the bouncer for the current request (plugins_loaded, priority 1). */
	public function run_firewall(): void {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || self::is_disabled() ) {
			return;
		}

		$firewall = new Firewall(
			$this->build_rules(),
			(array) $this->settings->get( 'allowlist' ),
			$this->settings->is_monitor_mode(),
			$this->log(),
			$this->store(),
			$this->geo()
		);

		$firewall->handle( $this->current_request(), new HttpResponder(), (string) $this->settings->get( 'block_message' ) );
	}

	/**
	 * Count a "not found" page towards the 404-flood ban (template_redirect).
	 *
	 * The ban itself is enforced by NotFoundFloodRule on the visitor's next request.
	 */
	public function track_not_found(): void {
		if ( ! is_404() || self::is_disabled() || $this->client_is_allowlisted() ) {
			return;
		}
		$rule   = new NotFoundFloodRule( $this->settings->rule( NotFoundFloodRule::ID ), $this->store() );
		$reason = $rule->record( $this->current_request() );
		if ( null === $reason ) {
			return;
		}
		$request = $this->current_request();
		$this->log()->record(
			array_merge(
				$this->log_context(),
				array(
					'ip'     => $request->ip(),
					'rule'   => NotFoundFloodRule::ID,
					'action' => BlockLogInterface::ACTION_LOCKOUT,
					'reason' => $reason,
				)
			)
		);
	}

	/** Purge old log rows (daily cron). */
	public function daily_maintenance(): void {
		$this->log()->purge_older_than( (int) $this->settings->get( 'log_retention_days' ) );
	}

	/** Brute-force protection hooks. */
	private function register_login_hooks(): void {
		add_action(
			'wp_login_failed',
			function ( $username ): void {
				if ( $this->client_is_allowlisted() ) {
					return;
				}
				$this->login_guard()->record_failure( $this->client_ip(), (string) $username, $this->log_context() );
			}
		);

		// Priority 999: runs after core's authenticators so we can override their result.
		add_filter( 'authenticate', array( $this, 'filter_authenticate' ), 999, 1 );
	}

	/**
	 * Refuse authentication from locked-out IPs and make error messages generic.
	 *
	 * This covers every login path, including XML-RPC, REST application
	 * passwords and custom login forms, not just wp-login.php.
	 *
	 * @param \WP_User|\WP_Error|null $user Result so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function filter_authenticate( $user ) {
		$guard = $this->login_guard();
		if ( ! $guard->is_enabled() ) {
			return $user;
		}

		if ( ! $this->settings->is_monitor_mode() && ! $this->client_is_allowlisted() ) {
			$remaining = $guard->lockout_remaining( $this->client_ip() );
			if ( $remaining > 0 ) {
				return new \WP_Error(
					'wp_bouncer_locked_out',
					sprintf(
						/* translators: %d: minutes until the lockout ends. */
						__( '<strong>Error:</strong> Too many failed login attempts. Please try again in %d minutes.', 'wp-bouncer' ),
						(int) ceil( $remaining / 60 )
					)
				);
			}
		}

		if ( $guard->wants_generic_errors() && is_wp_error( $user ) && array_intersect( $user->get_error_codes(), array( 'invalid_username', 'incorrect_password', 'invalid_email' ) ) ) {
			return new \WP_Error( 'wp_bouncer_invalid_credentials', __( '<strong>Error:</strong> The username or password you entered is incorrect.', 'wp-bouncer' ) );
		}
		return $user;
	}

	/** XML-RPC hardening that complements XmlRpcRule. */
	private function register_xmlrpc_hooks(): void {
		$rule = $this->settings->rule( XmlRpcRule::ID );
		if ( empty( $rule['enabled'] ) ) {
			return;
		}

		add_filter(
			'wp_headers',
			static function ( $headers ) {
				unset( $headers['X-Pingback'] );
				return $headers;
			}
		);
		remove_action( 'wp_head', 'rsd_link' );

		if ( 'block_abuse' === ( $rule['mode'] ?? 'block_all' ) ) {
			add_filter(
				'xmlrpc_methods',
				static function ( $methods ) {
					unset( $methods['system.multicall'], $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
					return $methods;
				}
			);
			return;
		}

		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'xmlrpc_methods', '__return_empty_array' );
	}

	/** Remove the users sitemap, which lists every author's username. */
	private function register_user_enumeration_hooks(): void {
		$rule = $this->settings->rule( UserEnumerationRule::ID );
		if ( empty( $rule['enabled'] ) ) {
			return;
		}
		add_filter(
			'wp_sitemaps_add_provider',
			static function ( $provider, $name ) {
				return 'users' === $name ? false : $provider;
			},
			10,
			2
		);
	}

	/**
	 * Request details to attach to log entries written outside the firewall.
	 *
	 * @return array<string, string>
	 */
	private function log_context(): array {
		$request = $this->current_request();
		return array(
			'method'     => $request->method(),
			'uri'        => $request->uri(),
			'user_agent' => $request->user_agent(),
			'country'    => (string) $this->geo()->lookup( $request->ip() ),
		);
	}
}
