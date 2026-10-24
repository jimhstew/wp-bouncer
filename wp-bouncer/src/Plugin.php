<?php
/**
 * Composition root: builds the services and connects them to WordPress hooks.
 *
 * @package WPBouncer
 */

namespace WPBouncer;

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\SetupNotices;
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
use WPBouncer\Log\BudgetedBlockLog;
use WPBouncer\Log\WriteBudget;
use WPBouncer\Login\LoginGuard;
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
use WPBouncer\Storage\CounterStoreInterface;
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

	public const VERSION = '1.1.2';

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
	 * Log write budget.
	 *
	 * @var WriteBudget|null
	 */
	private ?WriteBudget $write_budget = null;
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
		add_action( 'admin_init', array( $this, 'maybe_purge' ) );

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
		( new PrivacyTools( $this ) )->register();

		// Updates are not affected by WP_BOUNCER_DISABLE: updating is one way out of a bad version.
		if ( ! Updater::is_disabled() ) {
			( new Updater( $this->file ) )->register();
		}

		if ( is_admin() ) {
			( new SetupNotices( $this ) )->register();
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
		$this->guard            = null;
		$this->geo              = null;
		$this->geo_peer_trusted = null;
		// The IP settings may have changed, so resolve the client again.
		$this->resolver  = null;
		$this->client_ip = null;
		$this->request   = null;
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

	/**
	 * Log writer: the block log behind a per-minute write budget.
	 *
	 * Use this to record events. log() stays for reads, purging and the admin screens.
	 */
	public function log_writer(): BudgetedBlockLog {
		if ( null === $this->log_writer ) {
			$this->log_writer = new BudgetedBlockLog( $this->log(), $this->write_budget() );
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
			$priority           = max( 5, (int) apply_filters( 'wp_bouncer_log_priority_budget_per_minute', 30 ) );
			$this->write_budget = new WriteBudget( $this->store(), new Clock(), $per_minute, $priority );
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
			$this->guard = new LoginGuard(
				$this->settings->rule( LoginGuard::RULE_ID ),
				$this->store(),
				$this->log_writer(),
				null,
				static function ( string $name ): ?string {
					$id   = username_exists( $name );
					$user = $id ? get_userdata( (int) $id ) : false;
					return $user ? (string) $user->user_login : null;
				}
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
				static function (): bool {
					return function_exists( 'current_user_can' ) && current_user_can( 'manage_options' );
				},
				$this->ip_resolver()->is_local_request( wp_unslash( $_SERVER ) ),
				$this->client_can_be_banned(),
				$this->ip_resolver()->rejected_subject( wp_unslash( $_SERVER ) )
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
			new CountryRule( $s->rule( CountryRule::ID ), $this->geo(), ! empty( $s->rule( CountryRule::ID )['enabled'] ) && $this->country_paused() ),
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
			$this->build_rules(),
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
		$this->purge_logs();
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
			( new TrafficRecorder( $this ) )->purge();
		}
	}

	/** Brute-force protection hooks. */
	private function register_login_hooks(): void {
		add_action(
			'wp_login_failed',
			function ( $username ): void {
				if ( $this->client_is_allowlisted() ) {
					return;
				}
				if ( ! $this->client_can_be_banned() ) {
					$this->log_suspended_lockout();
					return;
				}
				$this->login_guard()->record_failure( $this->client_key(), (string) $username, array_merge( $this->log_context(), array( 'ip' => $this->client_ip() ) ) );
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

		if ( ! $this->settings->is_monitor_mode() && ! $this->client_is_allowlisted() && $this->client_can_be_banned() ) {
			$remaining = $guard->lockout_remaining( $this->client_key() );
			// Failures already at the limit: refuse now, before the lockout is written (shortens the race window).
			if ( 0 === $remaining && $guard->failures( $this->client_key() ) >= $guard->max_attempts() ) {
				$remaining = 60;
			}
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
