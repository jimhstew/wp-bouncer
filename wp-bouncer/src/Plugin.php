<?php
/**
 * Composition root: builds the services and connects them to WordPress hooks.
 *
 * @package WPBouncer
 */

namespace WPBouncer;

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\DashboardWidget;
use WPBouncer\Admin\DataNotices;
use WPBouncer\Admin\FirewallCapability;
use WPBouncer\Admin\SetupNotices;
use WPBouncer\Admin\ThreatMapPanel;
use WPBouncer\AdminLogins\AdminLoginRecorder;
use WPBouncer\AdminLogins\LoginHistoryRepository;
use WPBouncer\Alerts\AlertNotifier;
use WPBouncer\Audit\SettingsAuditor;
use WPBouncer\Audit\SettingsDriftMonitor;
use WPBouncer\Environment\EnvironmentAdmin;
use WPBouncer\Firewall\Firewall;
use WPBouncer\Firewall\HttpResponder;
use WPBouncer\Firewall\IpResolver;
use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;
use WPBouncer\Geo\ChainGeoProvider;
use WPBouncer\Geo\GeoDatabase;
use WPBouncer\Geo\GeoImport;
use WPBouncer\Geo\GeoProviderInterface;
use WPBouncer\Geo\HeaderGeoProvider;
use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Log\BlockLog;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Log\BudgetedBlockLog;
use WPBouncer\Log\WriteBudget;
use WPBouncer\Login\BasicAuthEditor;
use WPBouncer\Login\LoginGuard;
use WPBouncer\Privacy\AdminLoginPrivacy;
use WPBouncer\Privacy\PrivacyTools;
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
use WPBouncer\Storage\AtomicCounterInterface;
use WPBouncer\Storage\CounterStoreInterface;
use WPBouncer\Storage\ObjectCacheCounter;
use WPBouncer\Storage\RedactionMigration;
use WPBouncer\Storage\TableCounter;
use WPBouncer\Storage\TransientStore;
use WPBouncer\Support\Clock;
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

	public const VERSION = '1.3.0';

	/** Transient that limits the bad-filter log row to one a day. */
	private const BAD_RULES_TRANSIENT = 'wp_bouncer_bad_rules_logged';

	/** Internal state (not a setting): Unix time of the last log purge. */
	public const LAST_PURGE_OPTION = 'wp_bouncer_last_purge';

	/** Option holding metadata about the imported geo database. */
	public const GEO_META_OPTION = 'wp_bouncer_geo_meta';

	/**
	 * Shared plugin instance.
	 *
	 * @var Plugin|null
	 */
	private static ?Plugin $instance = null;

	/**
	 * Main plugin file.
	 *
	 * @var string
	 */
	private string $file;
	/**
	 * Settings for this component.
	 *
	 * @var Settings
	 */
	private Settings $settings;

	/**
	 * Counter store.
	 *
	 * @var CounterStoreInterface|null
	 */
	private ?CounterStoreInterface $store = null;
	/**
	 * Block log.
	 *
	 * @var BlockLog|null
	 */
	private ?BlockLog $log = null;
	/**
	 * Budgeted writer in front of the block log.
	 *
	 * @var BudgetedBlockLog|null
	 */
	private ?BudgetedBlockLog $log_writer = null;

	/**
	 * The log the current log writer was built on.
	 *
	 * @var BlockLog|null
	 */
	private ?BlockLog $log_writer_log = null;

	/**
	 * Log write budget.
	 *
	 * @var WriteBudget|null
	 */
	private ?WriteBudget $write_budget = null;
	/**
	 * Application-password check for Basic credentials.
	 *
	 * @var BasicAuthEditor|null
	 */
	private ?BasicAuthEditor $basic_auth_editor = null;
	/**
	 * Login failures already counted by the early application-password check in this request.
	 *
	 * Core's own count for the same attempt (application_password_failed_authentication or
	 * wp_login_failed) is skipped, once per early count, so an attempt counts exactly once.
	 *
	 * @var int
	 */
	private int $early_failures = 0;
	/**
	 * Country lookup.
	 *
	 * @var GeoProviderInterface|null
	 */
	private ?GeoProviderInterface $geo = null;
	/**
	 * Is this connection from a listed trusted proxy (memoised per request)?
	 *
	 * @var bool|null
	 */
	private ?bool $geo_peer_trusted = null;
	/**
	 * Geo database table.
	 *
	 * @var GeoDatabase|null
	 */
	private ?GeoDatabase $geo_db = null;
	/**
	 * Login failure tracker.
	 *
	 * @var LoginGuard|null
	 */
	private ?LoginGuard $guard = null;

	/**
	 * Did this request reserve a login attempt for a REST application-password check?
	 *
	 * @var bool
	 */
	private bool $app_reserved = false;

	/**
	 * Why the current authentication attempt is refused before the password is looked at
	 * (cross-site login post, or a blocked country under the login scope); null if it isn't.
	 *
	 * @var \WP_Error|null
	 */
	private ?\WP_Error $auth_refusal = null;

	/**
	 * Has the country refusal been written to the log for this request?
	 *
	 * @var bool
	 */
	private bool $country_logged = false;

	/**
	 * Has the cross-site Basic-auth refusal been written to the log for this request?
	 *
	 * @var bool
	 */
	private bool $foreign_basic_logged = false;

	/**
	 * Core authenticators taken off the authenticate filter for a refused attempt: callback => [priority, accepted args].
	 *
	 * @var array<string, array{0: int, 1: int}>
	 */
	private array $suspended_authenticators = array();

	/**
	 * Serial numbers of the screen_login_attempt() calls whose filter_authenticate() has not run yet (innermost last).
	 *
	 * @var int[]
	 */
	private array $auth_stack = array();

	/**
	 * Serial number of the last authenticate call.
	 *
	 * @var int
	 */
	private int $auth_serial = 0;

	/**
	 * The authenticate call that took the core authenticators off (0: none). Only that call puts them back.
	 *
	 * @var int
	 */
	private int $suspended_by = 0;

	/**
	 * Origins that count as this site, once the filters can no longer change (after init).
	 *
	 * @var array<int, string[]>
	 */
	private array $own_origins_cache = array();
	/**
	 * Cached request.
	 *
	 * @var Request|null
	 */
	private ?Request $request = null;
	/**
	 * Cached client IP.
	 *
	 * @var string|null
	 */
	private ?string $client_ip = null;
	/**
	 * Client IP resolver.
	 *
	 * @var IpResolver|null
	 */
	private ?IpResolver $resolver = null;
	/**
	 * Uploads guard.
	 *
	 * @var UploadsGuard|null
	 */
	private ?UploadsGuard $uploads = null;
	/**
	 * Alert notifier.
	 *
	 * @var AlertNotifier|null
	 */
	private ?AlertNotifier $alerts = null;

	/**
	 * Settings drift monitor.
	 *
	 * @var SettingsDriftMonitor|null
	 */
	private ?SettingsDriftMonitor $drift_monitor = null;

	/**
	 * The rule chain for this request (built once), shared by the firewall and the admin overview.
	 *
	 * @var RuleInterface[]|null
	 */
	private ?array $rules = null;

	/**
	 * Traffic log.
	 *
	 * @var TrafficLog|null
	 */
	private ?TrafficLog $traffic = null;

	/**
	 * Set up the Plugin.
	 *
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
		add_action(
			Installer::COUNTER_PURGE_HOOK,
			static function (): void {
				( new TableCounter() )->purge_expired();
			}
		);
		add_action(
			RedactionMigration::HOOK,
			static function (): void {
				RedactionMigration::cron( Installer::user_lookup() );
			}
		);
		add_action( 'admin_init', array( $this, 'maybe_purge' ) );
		add_action( 'admin_init', array( $this->alerts(), 'on_admin_init' ) );

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
		// Outside the is_disabled() branch: a write made while the switch is on is still audited.
		( new SettingsAuditor( $this ) )->register();
		// Admin screens only (not admin-ajax, so not Heartbeat): the monitor is never built on the front end.
		if ( is_admin() && ! wp_doing_ajax() ) {
			add_action( 'admin_init', array( $this, 'check_settings_drift' ) );
		}
		( new TrafficRecorder( $this ) )->register();
		( new PrivacyTools( $this ) )->register();
		( new AdminLoginPrivacy( null, $this ) )->register();
		( new AdminLoginRecorder( $this ) )->register();
		FirewallCapability::register();

		// Updates are not affected by WP_BOUNCER_DISABLE: updating is one way out of a bad version.
		if ( ! Updater::is_disabled() ) {
			( new Updater( $this->file ) )->register();
		}

		if ( is_admin() ) {
			( new SetupNotices( $this ) )->register();
			( new DataNotices() )->register();
			( new AdminController( $this ) )->register();
		}

		// Environment checks: built lazily when a screen asks (admin, Site Health, cron), never on the firewall path.
		if ( is_admin() || wp_doing_cron() ) {
			( new EnvironmentAdmin() )->register();
			( new DashboardWidget( $this ) )->register();
			( new ThreatMapPanel( $this ) )->register();
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

	/*
	 * ------------------------------------------------------------------
	 * Services (built lazily)
	 * ----------------------------------------------------------------
	 */

	/** Current settings. */
	public function settings(): Settings {
		return $this->settings;
	}

	/** Re-read settings after the admin saves them. */
	public function reload_settings(): void {
		$this->settings         = Settings::load();
		$this->rules            = null;
		$this->guard            = null;
		$this->geo              = null;
		$this->geo_peer_trusted = null;
		// The IP settings may have changed, so resolve the client again.
		$this->resolver  = null;
		$this->client_ip = null;
		$this->request   = null;
	}

	/**
	 * Run code as another site of a multisite network: that site's settings, Activity Log
	 * and log write budget. The services are put back afterwards, even on an exception.
	 *
	 * Only what login recording needs is swapped; the firewall's own objects are untouched.
	 *
	 * @param int      $blog_id Site ID.
	 * @param callable $callback Code to run.
	 */
	public function run_on_site( int $blog_id, callable $callback ): void {
		if ( ! is_multisite() || get_current_blog_id() === $blog_id ) {
			$callback();
			return;
		}
		$saved = array( $this->settings, $this->log, $this->log_writer, $this->write_budget );
		switch_to_blog( $blog_id );
		try {
			$this->settings     = Settings::load();
			$this->log          = null;
			$this->log_writer   = null;
			$this->write_budget = null;
			$callback();
		} finally {
			list( $this->settings, $this->log, $this->log_writer, $this->write_budget ) = $saved;
			restore_current_blog();
		}
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
		global $wpdb;
		// The table name is fixed when a BlockLog is built, so after switch_to_blog() it needs a new one.
		if ( null === $this->log || $this->log->table() !== $wpdb->prefix . 'bouncer_log' ) {
			$this->log = new BlockLog( $wpdb );
		}
		return $this->log;
	}

	/**
	 * Log writer: the block log behind a per-minute write budget.
	 *
	 * Use this to record events. log() stays for reads, purging and the admin screens.
	 */
	public function log_writer(): BudgetedBlockLog {
		$log = $this->log();
		// Rebuilt when log() was, so a writer made while another plugin had switched sites does not stay there.
		if ( null === $this->log_writer || $this->log_writer_log !== $log ) {
			$this->log_writer_log = $log;
			$this->log_writer     = new BudgetedBlockLog( $log, $this->write_budget() );
		}
		return $this->log_writer;
	}

	/** Site-wide log write budget (shared by the firewall and the log writer). */
	public function write_budget(): WriteBudget {
		if ( null === $this->write_budget ) {
			/**
			 * Filters how many block-log rows may be written per minute, site-wide (at least 10).
			 *
			 * @param int $per_minute Default 120.
			 */
			$per_minute = max( 10, (int) apply_filters( 'wp_bouncer_log_budget_per_minute', 120 ) );
			/**
			 * Filters the separate per-minute allowance for lockout and uploads-block rows (at least 5).
			 *
			 * @param int $per_minute Default 30.
			 */
			$priority = max( 5, (int) apply_filters( 'wp_bouncer_log_priority_budget_per_minute', 30 ) );
			/**
			 * Filters the separate per-minute allowance for administrator login rows (at least 5).
			 *
			 * @param int $per_minute Default 20.
			 */
			$login              = max( 5, (int) apply_filters( 'wp_bouncer_log_login_budget_per_minute', 20 ) );
			$this->write_budget = new WriteBudget( $this->store(), new Clock(), $per_minute, $priority, $login );
		}
		return $this->write_budget;
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
				$providers[] = new HeaderGeoProvider( wp_unslash( $_SERVER ), (string) $this->settings->get( 'geo_header' ), $this->client_ip(), $this->geo_headers_trusted() );
			}
			$meta = get_option( self::GEO_META_OPTION, array() );
			if ( ! empty( $meta['rows'] ) ) {
				$providers[] = $this->geo_database();
			}
			$this->geo = new ChainGeoProvider( $providers );
		}
		return $this->geo;
	}

	/**
	 * May request headers be believed as a geo source?
	 *
	 * Only when this connection comes from a listed trusted proxy (the
	 * effective list, as the IP resolver sees it).
	 */
	private function geo_headers_trusted(): bool {
		if ( null === $this->geo_peer_trusted ) {
			$server = wp_unslash( $_SERVER );
			$remote = isset( $server['REMOTE_ADDR'] ) && is_string( $server['REMOTE_ADDR'] ) ? $server['REMOTE_ADDR'] : '';
			$list   = $this->ip_resolver()->proxies();

			$this->geo_peer_trusted = '' !== $remote && IpUtils::is_valid( $remote ) && array() !== $list && IpUtils::matches_any( $remote, $list );
		}
		return $this->geo_peer_trusted;
	}

	/**
	 * Is the geo header unusable because of the configuration?
	 *
	 * True when the source is a request header (not a server variable) and
	 * no trusted proxy is listed, so the header can never be believed. This
	 * depends on settings only, not on who is connecting. With proxies listed
	 * but an unlisted peer, the header is ignored for that request without
	 * being "gated" here: the country is then unknown (fail closed).
	 */
	public function geo_header_gated(): bool {
		return 'header' === $this->settings->get( 'geo_source' )
			&& HeaderGeoProvider::KIND_HEADER === HeaderGeoProvider::kind( (string) $this->settings->get( 'geo_header' ) )
			&& array() === $this->ip_resolver()->proxies();
	}

	/** Is a geo database loaded? */
	public function geo_database_loaded(): bool {
		$meta = get_option( self::GEO_META_OPTION, array() );
		return is_array( $meta ) && ! empty( $meta['rows'] );
	}

	/** Is country blocking paused (header unusable by configuration and no database to fall back on)? */
	public function country_paused(): bool {
		return $this->geo_header_gated() && ! $this->geo_database_loaded();
	}

	/** Keeps PHP from running in the uploads folder. */
	public function uploads_guard(): UploadsGuard {
		if ( null === $this->uploads ) {
			$this->uploads = new UploadsGuard( $this );
		}
		return $this->uploads;
	}

	/** The settings drift monitor (built on first use). */
	public function drift_monitor(): SettingsDriftMonitor {
		if ( null === $this->drift_monitor ) {
			$this->drift_monitor = new SettingsDriftMonitor( $this );
		}
		return $this->drift_monitor;
	}

	/** Hourly admin check for settings changed outside WP Bouncer (hooked on admin_init). */
	public function check_settings_drift(): void {
		$this->drift_monitor()->on_admin_init();
	}

	/** Emails about new administrators and plugin changes. */
	public function alerts(): AlertNotifier {
		if ( null === $this->alerts ) {
			$this->alerts = new AlertNotifier( $this );
		}
		return $this->alerts;
	}

	/**
	 * Atomic login-attempt counter: the counters table, unless the site vouches that its
	 * persistent object cache is atomic and shared by every web server (Redis or Memcached).
	 * A cache that is per-process or evicts at will would silently lose counts.
	 */
	public function attempt_counter(): AtomicCounterInterface {
		/**
		 * Filters whether the object cache may hold the login counters.
		 *
		 * @param bool $atomic True to use wp_cache_incr(). Only for a shared Redis or Memcached.
		 */
		$use_cache = wp_using_ext_object_cache() && (bool) apply_filters( 'wp_bouncer_atomic_object_cache', false );
		return $use_cache ? new ObjectCacheCounter() : new TableCounter();
	}

	/** Brute-force tracker. */
	public function login_guard(): LoginGuard {
		if ( null === $this->guard ) {
			$this->guard = new LoginGuard(
				array_merge(
					$this->settings->rule( LoginGuard::RULE_ID ),
					/**
					 * Filters how many times the per-/64 login limit one IPv6 /48 may use.
					 *
					 * @param int $multiplier Default 8.
					 */
					array( 'wide_multiplier' => (int) apply_filters( 'wp_bouncer_ipv6_wide_multiplier', 8 ) )
				),
				$this->store(),
				$this->log_writer(),
				null,
				Installer::user_lookup(),
				$this->attempt_counter()
			);
		}
		return $this->guard;
	}

	/** True when wp-config.php defines WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS as true. */
	public static function allows_private_client_ips(): bool {
		return defined( 'WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS' ) && WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS;
	}

	/**
	 * Client IP resolver for the current settings.
	 *
	 * Honours the wp-config constant WP_BOUNCER_ALLOW_PRIVATE_CLIENT_IPS, for
	 * intranet sites whose proxy forwards private client addresses.
	 */
	public function ip_resolver(): IpResolver {
		if ( null === $this->resolver ) {
			$this->resolver = new IpResolver( (string) $this->settings->get( 'ip_source' ), (array) $this->settings->get( 'trusted_proxies' ), self::allows_private_client_ips() );
		}
		return $this->resolver;
	}

	/** Resolved client IP for this request. */
	public function client_ip(): string {
		if ( null === $this->client_ip ) {
			$this->client_ip = $this->ip_resolver()->resolve( wp_unslash( $_SERVER ) );
		}
		return $this->client_ip;
	}

	/**
	 * Does the current request skip every rule?
	 *
	 * True for a request from the server itself (loopback with no forwarding
	 * header) and for allowlisted IPs. Firewall::is_exempt() applies the same rule.
	 *
	 * @param string[]|null $allowlist Allowlist to test against; the saved one when null.
	 */
	public function client_is_exempt( ?array $allowlist = null ): bool {
		if ( $this->ip_resolver()->is_local_request( wp_unslash( $_SERVER ) ) ) {
			return true;
		}
		$ip = $this->client_ip();
		return '' !== $ip && IpUtils::matches_any( $ip, IpUtils::without_broad( $allowlist ?? (array) $this->settings->get( 'allowlist' ) ) );
	}

	/**
	 * Is the current client exempt from the rules (allowlisted, or the server itself)?
	 *
	 * @deprecated 1.1.2 The name is misleading since loopback is no longer an allowlist
	 *             entry. Use client_is_exempt().
	 */
	public function client_is_allowlisted(): bool {
		return $this->client_is_exempt();
	}

	/**
	 * Can the client IP be trusted enough to compare logins by location?
	 *
	 * False for no address, loopback, trusted-proxy addresses, a refused
	 * forwarding header, and a header IP source with no trusted proxies.
	 */
	public function client_ip_is_reliable(): bool {
		$ip = $this->client_ip();
		return '' !== $ip
			&& IpUtils::is_valid( $ip )
			&& '' === $this->ip_resolver()->rejected_subject( wp_unslash( $_SERVER ) )
			&& $this->client_can_be_banned();
	}

	/**
	 * May bans, lockouts and counters be kept against the current client?
	 *
	 * Not for loopback or trusted-proxy addresses, and not while a header IP
	 * source has no trusted proxies (the address is then a shared proxy).
	 */
	public function client_can_be_banned(): bool {
		$server = wp_unslash( $_SERVER );
		if ( '' !== $this->ip_resolver()->rejected_subject( $server ) ) {
			return true; // The "rejected:<proxy>" subject only matches requests that carry a refused header.
		}
		return IpUtils::is_bannable( $this->client_ip(), $this->ip_resolver()->proxies(), $this->ip_resolver()->suspends_bans( $server ) );
	}

	/**
	 * What bans, lockouts and counters are keyed on for the current client.
	 *
	 * The client IP, except when a trusted proxy forwarded a header whose value
	 * was refused: then "rejected:<proxy>", so such requests are still counted
	 * without ever banning the proxy itself.
	 */
	public function client_key(): string {
		$subject = $this->ip_resolver()->rejected_subject( wp_unslash( $_SERVER ) );
		return '' !== $subject ? $subject : $this->client_ip();
	}

	/**
	 * Who the Basic credentials on this request belong to, if they are a valid application password (memoised).
	 *
	 * Core accepts application passwords only after the firewall has run, so this checks the
	 * password itself, with no side effects. Nothing happens until a rule asks.
	 */
	private function basic_auth_editor(): BasicAuthEditor {
		if ( null === $this->basic_auth_editor ) {
			$this->basic_auth_editor = new BasicAuthEditor(
				wp_unslash( $_SERVER ),
				fn(): bool => $this->current_request()->is_api_auth_request(),
				fn(): bool => $this->refuses_foreign_basic_auth() || null !== $this->rest_country_refusal(),
				fn(): bool => $this->login_guard()->is_locked_out( $this->client_key() ),
				fn( string $name ) => $this->count_early_app_password_failure( $name )
			);
		}
		return $this->basic_auth_editor;
	}

	/** Snapshot of the current request. */
	public function current_request(): Request {
		if ( null === $this->request ) {
			// WordPress adds slashes to all superglobals early (wp_magic_quotes), so strip them.
			$this->request = Request::from_globals(
				$this->client_ip(),
				wp_unslash( $_SERVER ),
				wp_unslash( $_GET ),  // phpcs:ignore WordPress.Security.NonceVerification -- the firewall inspects every request, including those that can never carry a nonce; read-only inspection. The request URI (with query string) and parameter names can reach the block log, which escapes them on output.
				wp_unslash( $_POST ), // phpcs:ignore WordPress.Security.NonceVerification -- the firewall inspects every request, including those that can never carry a nonce; read-only inspection. The request URI (with query string) and parameter names can reach the block log, which escapes them on output.
				static function (): bool {
					return function_exists( 'is_user_logged_in' ) && is_user_logged_in();
				},
				function (): bool {
					return ( function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) || $this->basic_auth_editor()->is_admin();
				},
				$this->ip_resolver()->is_local_request( wp_unslash( $_SERVER ) ),
				$this->client_can_be_banned(),
				$this->ip_resolver()->rejected_subject( wp_unslash( $_SERVER ) ),
				fn(): array => $this->own_hosts(),
				static function (): bool {
					return function_exists( 'current_user_can' ) && current_user_can( 'edit_posts' );
				},
				fn(): bool => $this->basic_auth_editor()->is_editor(),
				static function ( string $nonce ): bool {
					return function_exists( 'wp_verify_nonce' ) && false !== wp_verify_nonce( $nonce, 'wp_rest' );
				}
			);
		}
		return $this->request;
	}

	/**
	 * The rule chain for this request, built once.
	 *
	 * The firewall and the admin overview share it, so "wp_bouncer_rules" runs once per request.
	 *
	 * @return RuleInterface[]
	 */
	public function registered_rules(): array {
		$this->rules ??= $this->build_rules();
		return $this->rules;
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
			$this->sensitive_file_rule(),
			$this->not_found_rule(),
			new LoginLockoutRule( $s->rule( LoginLockoutRule::ID ), $this->login_guard() ),
			new RateLimitRule( $s->rule( RateLimitRule::ID ), $this->store() ),
			new UserAgentRule( $s->rule( UserAgentRule::ID ) ),
			new XmlRpcRule( $s->rule( XmlRpcRule::ID ) ),
			new UserEnumerationRule( $s->rule( UserEnumerationRule::ID ) ),
			new CountryRule( $s->rule( CountryRule::ID ), $this->geo(), ! empty( $s->rule( CountryRule::ID )['enabled'] ) && $this->country_paused() ),
			new WafRule( $s->rule( WafRule::ID ) ),
		);

		/**
		 * Filter the firewall's rule chain.
		 *
		 * @param RuleInterface[] $rules  Rules in evaluation order.
		 * @param Plugin          $plugin Plugin instance.
		 */
		$filtered = apply_filters( 'wp_bouncer_rules', $rules, $this );
		if ( ! is_array( $filtered ) ) {
			// A callback that forgot "return" would otherwise switch the whole firewall off.
			$this->report_bad_rules_filter();
			$filtered = $rules;
		}

		return array_values(
			array_filter(
				$filtered,
				static function ( $rule ) {
					return $rule instanceof RuleInterface;
				}
			)
		);
	}

	/** Log (at most once a day) that a "wp_bouncer_rules" callback returned something other than an array. */
	private function report_bad_rules_filter(): void {
		if ( false !== get_transient( self::BAD_RULES_TRANSIENT ) ) {
			return;
		}
		set_transient( self::BAD_RULES_TRANSIENT, 1, DAY_IN_SECONDS );
		$this->log()->record(
			array(
				'rule'   => 'plugin',
				'action' => BlockLogInterface::ACTION_ALERT,
				'reason' => 'A wp_bouncer_rules filter callback returned a non-array (missing return?). The built-in rules are used.',
			)
		);
	}

	/*
	 * ------------------------------------------------------------------
	 * Hook callbacks
	 * ----------------------------------------------------------------
	 */

	/** Run the bouncer for the current request (plugins_loaded, priority 1). */
	public function run_firewall(): void {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || self::is_disabled() ) {
			return;
		}

		$firewall = new Firewall(
			$this->registered_rules(),
			IpUtils::without_broad( (array) $this->settings->get( 'allowlist' ) ),
			$this->settings->is_monitor_mode(),
			$this->log_writer(),
			$this->store(),
			$this->geo(),
			$this->write_budget()
		);

		// Blocking ends the request, so PCRE failures are recorded on shutdown.
		register_shutdown_function( array( $this, 'record_pcre_errors' ) );

		$firewall->handle( $this->current_request(), new HttpResponder(), (string) $this->settings->get( 'block_message' ) );
	}

	/**
	 * Remember PCRE failures seen by the WAF or the User-Agent rule (shutdown).
	 *
	 * Each signature or pattern is recorded at most once an hour, as the
	 * counter-store key "pcre_error:<id>" holding preg_last_error().
	 */
	public function record_pcre_errors(): void {
		$errors = array();
		$waf    = WafRule::last_error();
		if ( null !== $waf ) {
			$errors[ 'waf:' . $waf[0] ] = $waf[1];
		}
		foreach ( UserAgentRule::last_errors() as $pattern => $code ) {
			$errors[ 'ua:' . md5( (string) $pattern ) ] = $code;
		}
		foreach ( $errors as $id => $code ) {
			$key = 'pcre_error:' . $id;
			if ( null === $this->store()->get( $key ) ) {
				$this->store()->set( $key, $code, HOUR_IN_SECONDS );
			}
		}
	}

	/** The sensitive-file rule, with the bucket size for probes that another site's page caused. */
	private function sensitive_file_rule(): SensitiveFileRule {
		/**
		 * Filters how many sensitive-file probes caused by another site's page earn a ban.
		 *
		 * @param int $probes Default 5 (a probe from the visitor's own browsing needs 2).
		 */
		$probes = (int) apply_filters( 'wp_bouncer_cross_site_probe_limit', 5 );
		return new SensitiveFileRule( array_merge( $this->settings->rule( SensitiveFileRule::ID ), array( 'cross_site_probes' => max( 2, $probes ) ) ), $this->store(), $this->attempt_counter() );
	}

	/** The 404-flood rule, with the limit multiplier for 404s that another site's page caused. */
	private function not_found_rule(): NotFoundFloodRule {
		/**
		 * Filters how many times the 404 limit applies to 404s caused by another site's page.
		 *
		 * @param int $multiplier Default 5.
		 */
		$multiplier = (int) apply_filters( 'wp_bouncer_cross_site_404_multiplier', 5 );
		return new NotFoundFloodRule( array_merge( $this->settings->rule( NotFoundFloodRule::ID ), array( 'cross_site_multiplier' => max( 1, $multiplier ) ) ), $this->store(), $this->attempt_counter() );
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
		$rule   = $this->not_found_rule();
		$reason = $rule->record( $this->current_request() );
		if ( null === $reason ) {
			return;
		}
		$request = $this->current_request();
		$this->log_writer()->record(
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
		update_option( self::LAST_PURGE_OPTION, time(), true );
		$this->log_writer()->flush_summary();
		$this->alerts()->maybe_remind_disabled();
		$this->drift_monitor()->check( SettingsDriftMonitor::TRIGGER_CRON );
		$this->purge_logs();
		( new LoginHistoryRepository() )->prune_expired( AdminLoginRecorder::window_days() * DAY_IN_SECONDS );
		// Safety net: an interrupted upgrade must not leave the data migration unscheduled.
		RedactionMigration::schedule();
	}

	/** Purge the block log. */
	private function purge_logs(): void {
		$this->log()->purge_older_than( (int) $this->settings->get( 'log_retention_days' ) );
	}

	/**
	 * Fallback for sites where WP-Cron doesn't run: purge from an admin
	 * request when the last purge is more than two days old.
	 */
	public function maybe_purge(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( time() - (int) get_option( self::LAST_PURGE_OPTION, 0 ) > 2 * DAY_IN_SECONDS ) {
			// Claim the slot first so concurrent admin requests don't all purge.
			update_option( self::LAST_PURGE_OPTION, time(), true );
			$this->purge_logs();
			ThreatMapPanel::flush();
			( new LoginHistoryRepository() )->prune_expired( AdminLoginRecorder::window_days() * DAY_IN_SECONDS );
			( new TrafficRecorder( $this ) )->purge();
		}
	}

	/** Brute-force protection hooks. */
	private function register_login_hooks(): void {
		add_action(
			'wp_login_failed',
			function ( $username ): void {
				// A refused attempt (cross-site post, blocked country) was never checked: it is not a failure to count.
				if ( null !== $this->auth_refusal || $this->client_is_allowlisted() || $this->early_failure_already_counted() ) {
					return;
				}
				if ( ! $this->client_can_be_banned() ) {
					$this->log_suspended_lockout();
					return;
				}
				$this->login_guard()->record_failure( $this->client_key(), (string) $username, array_merge( $this->log_context(), array( 'ip' => $this->client_ip() ) ) );
			}
		);

		// Two-factor plugins can end the request from wp_login (the Two Factor plugin does, at priority 10),
		// after core accepted the password but before the request finishes. Release first of all.
		add_action(
			'wp_login',
			function (): void {
				$this->login_guard()->release( $this->client_key() );
			},
			-1,
			0
		);
		add_action( 'application_password_did_authenticate', array( $this, 'release_app_password_reservation' ), -1, 0 );

		// REST and XML-RPC application passwords (RT F1).
		add_action( 'application_password_failed_authentication', array( $this, 'count_app_password_failure' ) );
		add_filter( 'application_password_is_api_request', array( $this, 'refuse_app_password_when_locked' ) );
		add_filter( 'rest_authentication_errors', array( $this, 'filter_rest_authentication_errors' ), 100 );

		// A blocked country (login scope) also can't use lost-password, reset, registration, or get a session cookie (F8).
		foreach ( array( 'lostpassword_post', 'validate_password_reset' ) as $action ) {
			add_action( $action, array( $this, 'gate_country_action' ), 10, 1 );
		}
		foreach ( array( 'lostpassword_errors', 'registration_errors', 'woocommerce_registration_errors' ) as $filter ) {
			add_filter( $filter, array( $this, 'gate_country_errors' ), 10, 1 );
		}
		add_filter( 'send_auth_cookies', array( $this, 'gate_auth_cookies' ), 10, 6 );
		// Safety net: never leave core's authenticators off.
		add_action( 'shutdown', array( $this, 'restore_authenticators' ) );

		// Priority 0: refuse cross-site login posts and blocked countries before anything is reserved or counted (RT-05, RT-26).
		add_filter( 'authenticate', array( $this, 'screen_login_attempt' ), 0, 1 );

		// Priority 1: reserve the attempt before any password is checked (RT-08).
		add_filter( 'authenticate', array( $this, 'reserve_login_attempt' ), 1, 3 );

		// Priority 999: runs after core's authenticators so we can override their result.
		add_filter( 'authenticate', array( $this, 'filter_authenticate' ), 999, 1 );
	}

	/**
	 * Decide, before any reservation or password check, whether this attempt is refused outright.
	 *
	 * - A POST that the browser says another site started (or a sibling subdomain, unless its Origin is
	 *   this site's or on the allowed list) is refused on every path: wp-login.php, xmlrpc.php, WooCommerce
	 *   my-account, custom login URLs, admin-ajax logins. A forged page can't make a visitor fail logins,
	 *   and a forged header gets no guesses. The refusal also applies to allowlisted IPs: login CSRF
	 *   must stay blocked for them, and a refused attempt never counts against anyone.
	 * - With the country rule on the "login" scope, a blocked country is refused on every authentication path.
	 *
	 * A refused attempt is answered here with the error, and core's password authenticators are taken off the
	 * filter for the rest of the call, so no password is checked at all. filter_authenticate() (priority 999)
	 * puts them back and returns the same error as a backstop against plugins that would return a user.
	 * Nothing is reserved or counted.
	 *
	 * @param \WP_User|\WP_Error|null $user Result so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function screen_login_attempt( $user ) {
		$this->auth_stack[] = ++$this->auth_serial;
		$this->auth_refusal = null;
		if ( $this->settings->is_monitor_mode() ) {
			return $user;
		}
		$request = $this->current_request();
		if ( 'POST' === $request->method() && $this->login_guard()->is_enabled() && $request->is_foreign_credentials_request() ) {
			$this->auth_refusal = new \WP_Error( 'wp_bouncer_cross_site_login', __( '<strong>Error:</strong> Logging in from another site is not allowed.', 'wp-bouncer' ) );
			$this->log_auth_refusal( LoginGuard::RULE_ID, 'Login post from another site refused (Sec-Fetch-Site or Origin)' );
		} elseif ( null !== $this->refuse_country() ) {
			$this->auth_refusal = $this->country_error();
		}
		if ( null === $this->auth_refusal ) {
			return $user;
		}
		$this->suspend_core_authenticators( $this->auth_serial );
		return $this->auth_refusal;
	}

	/**
	 * The error shown to a visitor from a blocked country.
	 *
	 * @param int $status HTTP status for a REST error; 0 for none.
	 */
	private function country_error( int $status = 0 ): \WP_Error {
		return new \WP_Error( 'wp_bouncer_country_blocked', __( '<strong>Error:</strong> Logging in is not available from your location.', 'wp-bouncer' ), $status > 0 ? array( 'status' => $status ) : '' );
	}

	/**
	 * Take core's password authenticators off the authenticate filter for a refused attempt.
	 *
	 * @param int $serial The authenticate call doing it; only that call may put them back.
	 */
	private function suspend_core_authenticators( int $serial ): void {
		foreach ( array(
			'wp_authenticate_username_password'    => 3,
			'wp_authenticate_email_password'       => 3,
			'wp_authenticate_application_password' => 3,
			'wp_authenticate_spam_check'           => 2,
		) as $callback => $args ) {
			$priority = has_filter( 'authenticate', $callback );
			if ( false !== $priority ) {
				remove_filter( 'authenticate', $callback, $priority );
				$this->suspended_authenticators[ $callback ] = array( $priority, $args );
				$this->suspended_by                          = $serial;
			}
		}
	}

	/** Put back the authenticators taken off by suspend_core_authenticators(). */
	private function restore_core_authenticators(): void {
		foreach ( $this->suspended_authenticators as $callback => $info ) {
			add_filter( 'authenticate', $callback, $info[0], $info[1] );
		}
		$this->suspended_authenticators = array();
		$this->suspended_by             = 0;
	}

	/** Put the authenticators back whoever took them off (shutdown). */
	public function restore_authenticators(): void {
		$this->restore_core_authenticators();
	}

	/**
	 * The country verdict for the current request when the rule guards logins; logged once per request.
	 *
	 * Used for every way of signing in or getting a session. Respects the pause (an unusable database),
	 * the allowlist, local requests and monitor mode.
	 */
	public function refuse_country(): ?Verdict {
		$verdict = $this->country_refusal();
		if ( null !== $verdict && ! $this->country_logged ) {
			$this->country_logged = true;
			$this->log_auth_refusal( CountryRule::ID, $verdict->reason() );
		}
		return $verdict;
	}

	/**
	 * Add the country error to a lost-password, registration or password-reset error object.
	 *
	 * Hooked to lostpassword_post, lostpassword_errors, validate_password_reset, registration_errors
	 * and woocommerce_registration_errors, whose first argument is the WP_Error (a filter returns it).
	 *
	 * @param mixed $errors Errors so far.
	 * @return mixed
	 */
	public function gate_country_errors( $errors ) {
		if ( $errors instanceof \WP_Error && null !== $this->refuse_country() ) {
			$errors->add( 'wp_bouncer_country_blocked', __( '<strong>Error:</strong> This is not available from your location.', 'wp-bouncer' ) );
		}
		return $errors;
	}

	/**
	 * Action form of gate_country_errors() (lostpassword_post, validate_password_reset): the error object is changed in place.
	 *
	 * @param mixed $errors Errors so far.
	 */
	public function gate_country_action( $errors ): void {
		$this->gate_country_errors( $errors );
	}

	/**
	 * Don't issue a session cookie to a blocked country (send_auth_cookies), whichever plugin signs the user in.
	 *
	 * The session token WordPress already created is destroyed and the current user is cleared, so the
	 * session can't be picked up some other way.
	 *
	 * @param mixed $send       Whether to send the cookies.
	 * @param mixed $expire     Unused.
	 * @param mixed $expiration Unused.
	 * @param mixed $user_id    User ID.
	 * @param mixed $scheme     Unused.
	 * @param mixed $token      Session token.
	 * @return mixed
	 */
	public function gate_auth_cookies( $send, $expire = 0, $expiration = 0, $user_id = 0, $scheme = '', $token = '' ) {
		if ( ! $send || null === $this->refuse_country() ) {
			return $send;
		}
		if ( (int) $user_id > 0 && is_string( $token ) && '' !== $token ) {
			\WP_Session_Tokens::get_instance( (int) $user_id )->destroy( $token );
		}
		wp_set_current_user( 0 );
		return false;
	}

	/**
	 * The country rule's verdict for an authentication attempt, when the rule guards logins.
	 *
	 * Respects the pause (an unusable database), the allowlist, local requests and monitor mode.
	 */
	private function country_refusal(): ?Verdict {
		if ( $this->settings->is_monitor_mode() || $this->client_is_allowlisted() ) {
			return null;
		}
		$rule = $this->country_rule();
		return $rule->guards_authentication() ? $rule->decide( $this->current_request() ) : null;
	}

	/** The country rule built from the current settings (also used by the admin's "Blocked" badges). */
	public function country_rule(): CountryRule {
		$settings = $this->settings->rule( CountryRule::ID );
		return new CountryRule( $settings, $this->geo(), ! empty( $settings['enabled'] ) && $this->country_paused() );
	}

	/**
	 * Write a block row for an authentication attempt refused by screen_login_attempt().
	 *
	 * @param string $rule   Rule id.
	 * @param string $reason Reason.
	 */
	private function log_auth_refusal( string $rule, string $reason ): void {
		$this->log_writer()->record(
			array_merge(
				$this->log_context(),
				array(
					'ip'     => $this->client_ip(),
					'rule'   => $rule,
					'action' => BlockLogInterface::ACTION_BLOCKED,
					'reason' => $reason,
				)
			)
		);
	}

	/**
	 * Origins that count as this site: home URL, site URL, and the wp_bouncer_login_allowed_origins filter.
	 *
	 * The result is remembered only once `init` has run. Before that, a theme or other late code may still
	 * add to the filter, and a probe or 404 check that runs early (plugins_loaded) must not freeze an
	 * incomplete list for a login request later in the same process. Entries may be URLs, origins
	 * (scheme://host:port) or bare host names (any scheme).
	 *
	 * @return string[]
	 */
	private function own_hosts(): array {
		$blog = get_current_blog_id();
		if ( isset( $this->own_origins_cache[ $blog ] ) ) {
			return $this->own_origins_cache[ $blog ];
		}
		$extra   = apply_filters( 'wp_bouncer_login_allowed_origins', array() );
		$origins = array_values( array_unique( array_filter( array_map( 'strval', array_merge( array( home_url(), site_url() ), is_array( $extra ) ? $extra : array() ) ) ) ) );
		if ( did_action( 'init' ) ) {
			$this->own_origins_cache[ $blog ] = $origins;
		}
		return $origins;
	}

	/**
	 * Count a login attempt before core checks the password, so a burst of parallel
	 * guesses can't all slip under the limit. Returns $user unchanged.
	 *
	 * Known gap: a plugin that ends the request inside `authenticate` after the password
	 * check but before our priority-999 filter (some two-factor plugins) leaves the
	 * reservation counted as a failure. That errs on the side of locking out sooner, and the
	 * window expires it. Plugins that end the request from `wp_login` are covered (released at -1).
	 *
	 * @param \WP_User|\WP_Error|null $user     Result so far.
	 * @param mixed                   $username Typed username.
	 * @param mixed                   $password Typed password.
	 * @return \WP_User|\WP_Error|null
	 */
	public function reserve_login_attempt( $user, $username = '', $password = '' ) {
		if ( null === $this->auth_refusal && is_string( $username ) && '' !== $username && is_string( $password ) && '' !== $password && $this->counts_login_attempts() ) {
			$this->login_guard()->reserve( $this->client_key() );
		}
		return $user;
	}

	/**
	 * Count a wrong application password found by the early check (plugins_loaded).
	 *
	 * The request may be refused by a later rule before core checks the password, so core would
	 * never count it. Counted on the client's counter subject like any login failure.
	 *
	 * @param string $username User name as sent.
	 */
	public function count_early_app_password_failure( string $username ): void {
		if ( ! $this->counts_login_attempts() || $this->client_is_allowlisted() ) {
			return;
		}
		++$this->early_failures;
		$this->login_guard()->record_failure( $this->client_key(), sanitize_user( $username ), array_merge( $this->log_context(), array( 'ip' => $this->client_ip() ) ) );
	}

	/** Use up one early count, if there is one: core's count for the same attempt is then skipped. */
	private function early_failure_already_counted(): bool {
		if ( $this->early_failures > 0 ) {
			--$this->early_failures;
			return true;
		}
		return false;
	}

	/**
	 * Count a failed application-password check. Via XML-RPC the attempt already holds a
	 * reservation (counted once); via REST Basic auth nothing has counted it yet.
	 */
	public function count_app_password_failure(): void {
		$guard = $this->login_guard();
		if ( null !== $this->auth_refusal || $this->early_failure_already_counted() ) {
			return;
		}
		// An XML-RPC attempt holds a reservation made at priority 1; wp_login_failed settles it.
		if ( ! $this->counts_login_attempts() || ( $guard->has_reservation() && ! $this->app_reserved ) ) {
			return;
		}
		$this->app_reserved = false;
		$name               = isset( $_SERVER['PHP_AUTH_USER'] ) ? sanitize_user( wp_unslash( (string) $_SERVER['PHP_AUTH_USER'] ) ) : '';
		if ( $this->client_is_allowlisted() ) {
			return;
		}
		$guard->record_failure( $this->client_key(), $name, array_merge( $this->log_context(), array( 'ip' => $this->client_ip() ) ) );
	}

	/**
	 * Reserve the attempt for a REST application-password check, and don't let a locked-out
	 * client (or one past the limit) try at all: say it isn't an API request, so core skips the check.
	 *
	 * @param mixed $is_api_request Core's answer.
	 * @return mixed
	 */
	public function refuse_app_password_when_locked( $is_api_request ) {
		if ( ! $is_api_request ) {
			return $is_api_request;
		}
		// A credentials request that another site started is refused before any check, and not counted (F2):
		// a forged header only costs the sender the attempt.
		if ( $this->refuses_foreign_basic_auth() ) {
			return false;
		}
		// A blocked country can't use application passwords either (RT-26): say it isn't an API request, so core skips the check.
		if ( null !== $this->rest_country_refusal() ) {
			return false;
		}
		if ( ! $this->counts_login_attempts() ) {
			return $is_api_request;
		}
		$guard = $this->login_guard();
		$key   = $this->client_key();
		if ( $guard->is_locked_out( $key ) ) {
			return false;
		}
		// XML-RPC already reserved at authenticate priority 1; REST Basic auth has not.
		// A wrong password the early check already counted this request must not be counted again.
		if ( 0 === $this->early_failures && ! $guard->has_reservation() && $guard->reserve( $key ) > 0 ) {
			$this->app_reserved = true;
			if ( $guard->refusal_seconds( $key ) > 0 ) {
				return false;
			}
		}
		return $is_api_request;
	}

	/** An application password was accepted: give back the REST reservation. */
	public function release_app_password_reservation(): void {
		if ( $this->app_reserved ) {
			$this->login_guard()->release( $this->client_key() );
			$this->app_reserved = false;
		}
	}

	/**
	 * REST authentication result: a locked-out client using Basic auth gets a lockout error,
	 * and with generic errors on, credential errors stop saying which part was wrong.
	 *
	 * @param mixed $result Result so far (true, WP_Error or null).
	 * @return mixed
	 */
	public function filter_rest_authentication_errors( $result ) {
		if ( $this->refuses_foreign_basic_auth() ) {
			return new \WP_Error( 'wp_bouncer_cross_site_login', __( '<strong>Error:</strong> Logging in from another site is not allowed.', 'wp-bouncer' ), array( 'status' => 403 ) );
		}
		$country = $this->rest_country_refusal();
		if ( null !== $country ) {
			return $this->country_error( 403 );
		}
		$guard = $this->login_guard();
		if ( ! $guard->is_enabled() ) {
			return $result;
		}
		if ( $this->basic_auth_present() && $this->counts_login_attempts() && $guard->refusal_seconds( $this->client_key() ) > 0 ) {
			return new \WP_Error( 'wp_bouncer_locked_out', __( '<strong>Error:</strong> Too many failed login attempts. Please try again later.', 'wp-bouncer' ), array( 'status' => 403 ) );
		}
		if ( $guard->wants_generic_errors() && is_wp_error( $result ) && array_intersect( $result->get_error_codes(), array( 'invalid_username', 'invalid_email', 'incorrect_password', 'application_passwords_disabled_for_user' ) ) ) {
			return new \WP_Error( 'wp_bouncer_invalid_credentials', __( '<strong>Error:</strong> The username or password you entered is incorrect.', 'wp-bouncer' ), array( 'status' => 401 ) );
		}
		return $result;
	}

	/**
	 * Does the request carry Basic-auth credentials (REST application passwords)?
	 *
	 * Core copies an Authorization header into PHP_AUTH_USER and PHP_AUTH_PW when the server doesn't
	 * (including after the application-password filter has run), so the raw header is checked too.
	 */
	private function basic_auth_present(): bool {
		if ( isset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] ) ) {
			return true;
		}
		foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $key ) {
			if ( isset( $_SERVER[ $key ] ) && is_string( $_SERVER[ $key ] ) && 0 === stripos( ltrim( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) ), 'basic ' ) ) {
				return true;
			}
		}
		return false;
	}

	/** Is this a Basic-auth request that another site started, with login protection on and enforcing? Logged once. */
	private function refuses_foreign_basic_auth(): bool {
		if ( ! $this->basic_auth_present() || $this->settings->is_monitor_mode() || ! $this->login_guard()->is_enabled() || ! $this->current_request()->is_foreign_credentials_request() ) {
			return false;
		}
		if ( ! $this->foreign_basic_logged ) {
			$this->foreign_basic_logged = true;
			$this->log_auth_refusal( LoginGuard::RULE_ID, 'Application-password request from another site refused (Sec-Fetch-Site or Origin)' );
		}
		return true;
	}

	/** The country verdict for a REST request that carries Basic-auth credentials, or null. */
	private function rest_country_refusal(): ?Verdict {
		return $this->basic_auth_present() ? $this->refuse_country() : null;
	}

	/** Are login attempts from this client counted (enabled, enforcing, not allowlisted, bannable)? */
	private function counts_login_attempts(): bool {
		return $this->login_guard()->is_enabled() && ! $this->settings->is_monitor_mode() && ! $this->client_is_allowlisted() && $this->client_can_be_banned();
	}

	/**
	 * Refuse authentication from locked-out IPs and make error messages generic.
	 *
	 * This covers every path that goes through the `authenticate` filter:
	 * wp-login.php, XML-RPC and custom login forms. REST application
	 * passwords bypass that filter (core checks them on determine_current_user),
	 * so they are handled by count_app_password_failure(),
	 * refuse_app_password_when_locked() and filter_rest_authentication_errors().
	 *
	 * @param \WP_User|\WP_Error|null $user Result so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function filter_authenticate( $user ) {
		// Refused before the password was looked at (screen_login_attempt()); nothing was reserved.
		$serial = (int) array_pop( $this->auth_stack );
		if ( null !== $this->auth_refusal ) {
			// Only the call that took the authenticators off puts them back: a nested call must not re-enable them for the outer one.
			if ( 0 !== $serial && $serial === $this->suspended_by ) {
				$this->restore_core_authenticators();
			}
			return $this->auth_refusal;
		}
		$guard = $this->login_guard();
		if ( ! $guard->is_enabled() ) {
			return $user;
		}

		if ( $this->counts_login_attempts() ) {
			// A lockout, or an attempt reserved past the limit (or failures already at it): refuse whatever the password check said.
			$remaining = $guard->refusal_seconds( $this->client_key() );
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

		if ( $user instanceof \WP_User ) {
			$guard->release( $this->client_key() );
		}

		if ( $guard->wants_generic_errors() && is_wp_error( $user ) && array_intersect( $user->get_error_codes(), array( 'invalid_username', 'incorrect_password', 'invalid_email' ) ) ) {
			return new \WP_Error( 'wp_bouncer_invalid_credentials', __( '<strong>Error:</strong> The username or password you entered is incorrect.', 'wp-bouncer' ) );
		}
		return $user;
	}

	/**
	 * Note, instead of counting, a failed login whose lockout is suspended.
	 *
	 * While a header IP source has no trusted proxies every visitor appears to
	 * come from the proxy, so a lockout would refuse them all. The failure is
	 * logged as "monitored" (once a minute per address) so the admin can see
	 * what would have happened.
	 */
	private function log_suspended_lockout(): void {
		$ip = $this->client_ip();
		if ( '' === $ip || ! $this->ip_resolver()->suspends_bans( wp_unslash( $_SERVER ) ) || ! $this->login_guard()->is_enabled() ) {
			return;
		}
		$key = 'fb_login_log:' . $ip;
		if ( null !== $this->store()->get( $key ) ) {
			return;
		}
		if ( ! $this->write_budget()->peek( LoginGuard::RULE_ID ) ) {
			return;
		}
		$this->store()->set( $key, 1, Firewall::LOG_DEDUPE_SECONDS );
		$this->log_writer()->record(
			array_merge(
				$this->log_context(),
				array(
					'ip'     => $ip,
					'rule'   => LoginGuard::RULE_ID,
					'action' => BlockLogInterface::ACTION_MONITORED,
					'reason' => 'Failed login. Lockouts are suspended because the client IP cannot be told apart from a shared proxy (IP header set, but the connection is not from a listed trusted proxy).',
				)
			)
		);
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
		add_filter( 'oembed_response_data', array( $this, 'filter_oembed_response' ), 10, 1 );
		if ( ! empty( $rule['block_rest_users'] ) ) {
			add_filter( 'rest_prepare_user', array( $this, 'filter_rest_user' ), 10, 1 );
		}
		if ( $this->login_guard()->wants_generic_errors() ) {
			add_filter( 'lostpassword_errors', array( $this, 'filter_lostpassword_errors' ), 10, 1 );
		}
		// WordPress 7.0 answers a request for a missing sitemap provider with a 200 page
		// instead of a 404 (7.1 fixed it), so answer it here, before WP_Sitemaps does (priority 10).
		add_action( 'template_redirect', array( $this, 'block_users_sitemap' ), 1 );
	}

	/**
	 * Drop the author fields from oEmbed responses (oembed_response_data).
	 *
	 * @param mixed $data Response data.
	 * @return mixed
	 */
	public function filter_oembed_response( $data ) {
		if ( is_array( $data ) ) {
			unset( $data['author_name'], $data['author_url'] );
		}
		return $data;
	}

	/**
	 * Hide the username-bearing fields of user objects from logged-out visitors (rest_prepare_user).
	 *
	 * Covers users embedded in other responses (for example a post's author
	 * with _embed), which the route check does not see.
	 *
	 * @param mixed $response REST response for one user.
	 * @return mixed
	 */
	public function filter_rest_user( $response ) {
		if ( $response instanceof \WP_REST_Response && ! is_user_logged_in() ) {
			$data = $response->get_data();
			if ( is_array( $data ) ) {
				unset( $data['slug'], $data['name'], $data['link'] );
				$response->set_data( $data );
			}
		}
		return $response;
	}

	/**
	 * Give the "no account with that email address" lost-password error the generic wording (lostpassword_errors).
	 *
	 * Only the invalid_email error exists when this filter runs. For an unknown
	 * username core adds invalidcombo after the filter, so that message cannot
	 * be changed here, and both cases still differ from the success message.
	 *
	 * @param mixed $errors Errors so far.
	 * @return mixed
	 */
	public function filter_lostpassword_errors( $errors ) {
		if ( $errors instanceof \WP_Error && in_array( 'invalid_email', $errors->get_error_codes(), true ) ) {
			$errors->remove( 'invalid_email' );
			$errors->add( 'wp_bouncer_lostpassword', __( '<strong>Error:</strong> A password reset could not be started for that username or email address.', 'wp-bouncer' ) );
		}
		return $errors;
	}

	/**
	 * Answer a request for the users sitemap with a 404 (template_redirect, priority 1).
	 *
	 * The provider is removed, but WordPress 7.0 then falls through to a normal page.
	 */
	public function block_users_sitemap(): void {
		global $wp_query;
		if ( ! $wp_query instanceof \WP_Query || 'users' !== $wp_query->get( 'sitemap' ) ) {
			return;
		}
		$wp_query->set( 'sitemap', '' ); // So WP_Sitemaps::render_sitemaps() has nothing to render.
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
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
