<?php
/**
 * Records successful administrator logins in the Activity Log.
 *
 * @package WPBouncer
 */

namespace WPBouncer\AdminLogins;

use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Plugin;
use WPBouncer\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Integration class. Hooks run after authentication succeeded, at priority 20.
 * Nothing here may make a login fail: the whole of handle() runs inside a
 * try/catch and never returns a value.
 */
final class AdminLoginRecorder {

	public const LOG_RULE = 'admin_login';

	/** Seconds the same application-password or XML-RPC login from one range is recorded only once. */
	private const DEDUPE_TTL = 3600;

	/** Most sites one login is recorded on (multisite): a bound on the work done in one request. */
	public const MAX_SITES = 100;

	/**
	 * Plugin.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;
	/**
	 * User IDs already handled in this request.
	 *
	 * @var array<int, bool>
	 */
	private array $recorded = array();
	/**
	 * User IDs being handled right now. Set before any filter runs, so a filter that
	 * asks who the current user is can't re-enter handle() for the same user.
	 *
	 * @var array<int, bool>
	 */
	private array $in_progress = array();
	/**
	 * User IDs that passed the authenticate filter on an XML-RPC request.
	 *
	 * @var array<int, bool>
	 */
	private array $xmlrpc_auth = array();
	/**
	 * User IDs whose XML-RPC authentication was an application password (already recorded or deduped under that label).
	 *
	 * @var array<int, bool>
	 */
	private array $app_auth = array();
	/**
	 * Multisite application-password and XML-RPC logins noticed during authentication, recorded on shutdown.
	 *
	 * @var array<int, array{0: \WP_User, 1: string, 2: int}>
	 */
	private array $pending = array();

	/**
	 * Set up the AdminLoginRecorder.
	 *
	 * @param Plugin $plugin Plugin.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/** Register hooks. Reads no option and runs no query. */
	public function register(): void {
		add_action( 'wp_login', array( $this, 'on_wp_login' ), 20, 2 );
		add_action( 'application_password_did_authenticate', array( $this, 'on_application_password' ), 20, 2 );
		add_action( 'two_factor_user_authenticated', array( $this, 'on_second_factor' ), 20, 1 );
		add_action( 'wp_bouncer_record_admin_login', array( $this, 'on_second_factor' ), 10, 1 );
		add_action( 'delete_user', array( $this, 'on_user_deleted' ), 10, 1 );
		add_action( 'wpmu_delete_user', array( $this, 'on_user_deleted' ), 10, 1 );
		// Flush at the first safe point after authentication. WordPress's fatal error handler can end the
		// request before "shutdown" fires, so shutdown is only the fallback. flush_pending() is idempotent.
		add_filter( 'rest_pre_dispatch', array( $this, 'flush_pending_filter' ), 0, 1 );
		add_action( 'wp_loaded', array( $this, 'flush_pending' ), 20 );
		add_action( 'shutdown', array( $this, 'flush_pending' ), 0 );
		add_action( 'remove_user_from_blog', array( $this, 'on_user_removed_from_site' ), 10, 2 );

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			add_filter( 'authenticate', array( $this, 'note_xmlrpc_authentication' ), PHP_INT_MAX, 1 );
			add_action( 'xmlrpc_call', array( $this, 'flush_pending' ), 0, 0 );
			add_action( 'xmlrpc_call', array( $this, 'on_xmlrpc_call' ), 20, 0 );
		}
	}

	/**
	 * An interactive login.
	 *
	 * @param mixed $login Login name (unused).
	 * @param mixed $user  The user.
	 */
	public function on_wp_login( $login, $user = null ): void {
		unset( $login );
		if ( $user instanceof \WP_User ) {
			$this->handle( $user, LoginEvent::METHOD_INTERACTIVE );
		}
	}

	/**
	 * An application-password login. Never ask who the current user is here:
	 * this runs inside determine_current_user.
	 *
	 * @param mixed $user The user.
	 * @param mixed $item The application password (ignored, its name is never stored).
	 */
	public function on_application_password( $user, $item = null ): void {
		unset( $item );
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		$xmlrpc = ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST );
		if ( ! $xmlrpc ) {
			try {
				$xmlrpc = $this->plugin->current_request()->is_xmlrpc();
			} catch ( \Throwable $e ) {
				$xmlrpc = false;
			}
		}
		$method = $xmlrpc ? LoginEvent::METHOD_APP_XMLRPC : LoginEvent::METHOD_APP_REST;
		if ( $xmlrpc ) {
			// Set even when the dedupe cache hides the login: on_xmlrpc_call must not add a password row (RT-16).
			$this->app_auth[ (int) $user->ID ] = true;
		}
		if ( is_multisite() && ( doing_filter( 'determine_current_user' ) || doing_filter( 'authenticate' ) ) ) {
			// Recording on other sites switches blogs, which must not happen mid-authentication. Wait for shutdown.
			if ( ! isset( $this->pending[ (int) $user->ID ] ) ) {
				$this->pending[ (int) $user->ID ] = array( $user, $method, get_current_blog_id() );
			}
			return;
		}
		$this->handle( $user, $method );
	}

	/**
	 * The rest_pre_dispatch filter form of flush_pending(). Returns the value unchanged.
	 *
	 * @param mixed $result Pre-dispatch result.
	 * @return mixed
	 */
	public function flush_pending_filter( $result ) {
		$this->flush_pending();
		return $result;
	}

	/**
	 * Record the logins queued during authentication (multisite). Safe to call repeatedly: the queue is
	 * emptied first. Does nothing while authentication is still running (no blog switching there).
	 */
	public function flush_pending(): void {
		if ( array() === $this->pending || doing_filter( 'determine_current_user' ) || doing_filter( 'authenticate' ) ) {
			return;
		}
		$pending       = $this->pending;
		$this->pending = array();
		foreach ( $pending as $item ) {
			$this->handle( $item[0], $item[1], $item[2] );
		}
	}

	/**
	 * A second factor passed (Two Factor plugin, or another plugin firing our action).
	 *
	 * @param mixed $user The user.
	 */
	public function on_second_factor( $user ): void {
		if ( $user instanceof \WP_User ) {
			$this->handle( $user, LoginEvent::METHOD_INTERACTIVE_2FA );
		}
	}

	/**
	 * A user is being deleted. On a single site or for a network delete (wpmu_delete_user) their
	 * location history on this site goes. On a network a "delete user" on one site only removes
	 * them from it, so the history becomes a tombstone: re-adding the account can't start a silent history.
	 *
	 * @param mixed $user_id User ID.
	 */
	public function on_user_deleted( $user_id ): void {
		if ( (int) $user_id <= 0 ) {
			return;
		}
		$repo = new LoginHistoryRepository();
		if ( is_multisite() && 'wpmu_delete_user' !== current_action() ) {
			$repo->tombstone_for_blog( (int) $user_id, get_current_blog_id(), time() );
			return;
		}
		$repo->delete( (int) $user_id );
	}

	/**
	 * A user was removed from a site. Their history for that site becomes a tombstone on a network
	 * (a returning account alerts), and is deleted on a single site.
	 *
	 * @param mixed $user_id User ID.
	 * @param mixed $blog_id Site ID.
	 */
	public function on_user_removed_from_site( $user_id, $blog_id = 0 ): void {
		if ( (int) $user_id > 0 && (int) $blog_id > 0 ) {
			$repo = new LoginHistoryRepository();
			if ( is_multisite() ) {
				$repo->tombstone_for_blog( (int) $user_id, (int) $blog_id, time() );
			} else {
				$repo->delete_for_blog( (int) $user_id, (int) $blog_id );
			}
		}
	}

	/**
	 * XML-RPC only: remember who authenticated. Returns the value unchanged.
	 *
	 * @param mixed $user Result of the authenticate filter chain.
	 * @return mixed
	 */
	public function note_xmlrpc_authentication( $user ) {
		if ( $user instanceof \WP_User ) {
			$this->xmlrpc_auth[ (int) $user->ID ] = true;
		}
		return $user;
	}

	/** XML-RPC only: a call is being made; record a password login that fired no wp_login. */
	public function on_xmlrpc_call(): void {
		try {
			$id = (int) get_current_user_id();
			if ( $id > 0 && ! empty( $this->xmlrpc_auth[ $id ] ) && empty( $this->app_auth[ $id ] ) && empty( $this->recorded[ $id ] ) && ! isset( $this->pending[ $id ] ) ) {
				$user = get_userdata( $id );
				if ( $user instanceof \WP_User ) {
					$this->handle( $user, LoginEvent::METHOD_XMLRPC_PASSWORD );
				}
			}
		} catch ( \Throwable $e ) {
			$this->report( $e );
		}
	}

	/**
	 * Record one login. Never throws.
	 *
	 * @param \WP_User $user   The user.
	 * @param string   $method One of the LoginEvent::METHOD_* constants.
	 * @param int      $origin Site the login happened on; 0 means the current site.
	 */
	public function handle( \WP_User $user, string $method, int $origin = 0 ): void {
		$id = (int) $user->ID;
		// First thing, before any filter or capability check can run and call back into us.
		if ( isset( $this->in_progress[ $id ] ) ) {
			return;
		}
		$this->in_progress[ $id ] = true;
		try {
			$this->record( $user, $method, $origin );
		} catch ( \Throwable $e ) {
			$this->report( $e );
		} finally {
			unset( $this->in_progress[ $id ] );
		}
	}

	/**
	 * Debug log only, and only when the site asked for it.
	 *
	 * @param \Throwable $e What went wrong.
	 */
	private function report( \Throwable $e ): void {
		if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			error_log( 'WP Bouncer: admin login not recorded: ' . get_class( $e ) . ': ' . $e->getMessage() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- debug log only.
		}
	}

	/**
	 * The recording flow. Pass 1 finds the sites where this login counts, using only
	 * each site's switch and the user's role there. Pass 2 records on each of them.
	 *
	 * @param \WP_User $user   The user.
	 * @param string   $method One of the LoginEvent::METHOD_* constants.
	 * @param int      $origin Site the login happened on; 0 means the current site.
	 */
	private function record( \WP_User $user, string $method, int $origin = 0 ): void {
		$id = (int) $user->ID;
		if ( $id <= 0 || ! empty( $this->recorded[ $id ] ) ) {
			return;
		}
		$origin = $origin > 0 ? $origin : get_current_blog_id();
		$ip     = $this->plugin->client_ip();
		$range  = LoginLocationPolicy::range_of( $ip );
		$dedupe = null;
		if ( LoginEvent::METHOD_INTERACTIVE !== $method && LoginEvent::METHOD_INTERACTIVE_2FA !== $method ) {
			// Repeated application-password and XML-RPC calls from one range: one store read, no geo lookup,
			// and on a network no site list either. The key is set once a recording succeeded.
			// A super admin is recorded only on the origin site, so the key must name it: a login on site 2
			// must not hide one on site 1. Site admins are recorded on all their sites in one go, so their
			// key stays network-wide (plus a hash of their site set, RT-17) and a repeat request still costs one read and no blog switch.
			$scope  = $this->dedupe_scope( $id, $origin );
			$dedupe = 'login_seen:' . $user->ID . '|' . $range . '|' . $method . $scope;
			if ( $this->dedupe_seen( $dedupe ) ) {
				return;
			}
		}
		$network = is_multisite() ? (array) get_site_option( 'active_sitewide_plugins', array() ) : array();
		$active  = isset( $network[ plugin_basename( $this->plugin->file() ) ] );
		$matched = false;
		$sites   = array();
		foreach ( $this->candidate_sites( $user, $origin ) as $blog_id ) {
			try {
				$this->plugin->run_on_site(
					$blog_id,
					function () use ( $user, $blog_id, $origin, $active, &$matched, &$sites ): void {
						if ( $blog_id !== $origin && ! $this->runs_here( $active ) ) {
							return;
						}
						$alerts = $this->plugin->settings()->get( 'alerts' );
						if ( ! is_array( $alerts ) || empty( $alerts['record_admin_logins'] ) ) {
							return;
						}
						// Capabilities are per site: judge the account as it is on the site being checked.
						$here = $blog_id === $origin ? $user : new \WP_User( $user->ID );
						if ( ! $this->is_admin( $here ) ) {
							return;
						}
						$matched = true;
						$sites[] = $blog_id;
					}
				);
			} catch ( \Throwable $e ) {
				$this->report( $e );
			}
		}
		if ( ! $matched ) {
			return;
		}
		if ( LoginEvent::METHOD_INTERACTIVE === $method && $this->defer_to_second_factor( $user, $method ) ) {
			// The login is not complete yet. Nothing is recorded and no history saved until the second factor passes.
			return;
		}
		$this->recorded[ $id ] = true;
		if ( array() === $sites ) {
			return;
		}

		$country  = '' !== $ip ? (string) $this->plugin->geo()->lookup( $ip ) : '';
		$country  = preg_match( '/^[A-Z]{2}$/', $country ) ? $country : '';
		$reliable = $this->plugin->client_ip_is_reliable();
		$request  = $this->plugin->current_request();
		$facts    = array( $ip, $range, $country, $reliable, $request->method(), $request->uri(), $request->user_agent() );

		$marked = false;
		foreach ( $sites as $blog_id ) {
			try {
				$this->plugin->run_on_site(
					$blog_id,
					function () use ( $user, $method, $facts ): void {
						$this->record_on_site( $user, $method, $facts );
					}
				);
				if ( ! $marked && null !== $dedupe ) {
					$this->dedupe_mark( $dedupe );
					$marked = true;
				}
			} catch ( \Throwable $e ) {
				// One site failing must not skip the others.
				$this->report( $e );
			}
		}
	}

	/**
	 * Does the plugin run on the current (switched) site: network-active or active here, with saved settings?
	 *
	 * @param bool $network_active Whether the plugin is network-active.
	 */
	private function runs_here( bool $network_active ): bool {
		if ( ! $network_active && ! in_array( plugin_basename( $this->plugin->file() ), (array) get_option( 'active_plugins', array() ), true ) ) {
			return false;
		}
		return false !== get_option( Settings::OPTION, false );
	}

	/**
	 * Has this application-password or XML-RPC login been recorded within the hour?
	 *
	 * @param string $key Logical key.
	 */
	private function dedupe_seen( string $key ): bool {
		if ( is_multisite() ) {
			return (bool) get_site_transient( 'wpb_' . md5( $key ) );
		}
		return (bool) $this->plugin->store()->get( $key );
	}

	/**
	 * Remember a recorded application-password or XML-RPC login for an hour. On a network the
	 * key is shared by every site, so repeated API requests cost one read.
	 *
	 * @param string $key Logical key.
	 */
	private function dedupe_mark( string $key ): void {
		if ( is_multisite() ) {
			set_site_transient( 'wpb_' . md5( $key ), 1, self::DEDUPE_TTL );
			return;
		}
		$this->plugin->store()->set( $key, 1, self::DEDUPE_TTL );
	}

	/**
	 * The part of the dedupe key that names where this login is recorded. A super administrator is
	 * recorded on the origin site only. A site administrator's key carries a short hash of the sites
	 * their meta lists (no site switch, no get_site()), so a newly granted site is not hidden by an
	 * earlier recording; the origin is named too when the meta does not list it (RT-17).
	 *
	 * @param int $id     User ID.
	 * @param int $origin Site the login happened on.
	 */
	private function dedupe_scope( int $id, int $origin ): string {
		if ( ! is_multisite() ) {
			return '';
		}
		if ( is_super_admin( $id ) ) {
			return '|b' . $origin;
		}
		$ids = $this->meta_sites( $id, $origin );
		sort( $ids );
		return '|s' . substr( md5( implode( ',', $ids ) ), 0, 8 ) . ( in_array( $origin, $ids, true ) ? '' : '|b' . $origin );
	}

	/**
	 * Sites whose capabilities meta may make this user an administrator, read from the user's own meta
	 * (one cached read, no switching). The origin is listed when it qualifies and does not count toward the cap.
	 * get_blogs_of_user() would load each site's details with switch_to_blog(), which asks who the current
	 * user is mid-authentication.
	 *
	 * @param int $user_id User ID.
	 * @param int $origin  Site the login happened on.
	 * @return int[] Site IDs, unfiltered by site state.
	 */
	private function meta_sites( int $user_id, int $origin ): array {
		global $wpdb;
		$ids     = array();
		$checked = 0;
		$base    = '/^' . preg_quote( $wpdb->base_prefix, '/' ) . '(?:(\d+)_)?capabilities$/';
		foreach ( array_keys( (array) get_user_meta( $user_id ) ) as $key ) {
			if ( ! preg_match( $base, (string) $key, $m ) ) {
				continue;
			}
			// The key without a number belongs to site 1.
			$blog_id = isset( $m[1] ) && '' !== $m[1] ? (int) $m[1] : 1;
			if ( isset( $ids[ $blog_id ] ) || ! self::may_be_admin( get_user_meta( $user_id, (string) $key, true ) ) ) {
				continue;
			}
			if ( $blog_id !== $origin && ++$checked > self::MAX_SITES ) {
				break;
			}
			$ids[ $blog_id ] = $blog_id;
		}
		return array_values( $ids );
	}

	/**
	 * Sites where this login may count: the current site, or on multisite, for a site
	 * administrator, the sites they belong to (the current one first, at most MAX_SITES).
	 * A super administrator's login counts where it happened.
	 *
	 * @param \WP_User $user   The user.
	 * @param int      $origin Site the login happened on; 0 means the current site.
	 * @return int[] Site IDs.
	 */
	private function candidate_sites( \WP_User $user, int $origin = 0 ): array {
		$current = $origin > 0 ? $origin : get_current_blog_id();
		if ( ! is_multisite() || is_super_admin( $user->ID ) ) {
			return array( $current );
		}
		$ids = array();
		foreach ( $this->meta_sites( (int) $user->ID, $current ) as $blog_id ) {
			if ( $blog_id === $current ) {
				continue;
			}
			$site = get_site( $blog_id );
			if ( $site instanceof \WP_Site && ! $site->deleted && ! $site->archived && ! $site->spam ) {
				$ids[] = $blog_id;
			}
		}
		// A user who isn't a member of the current site (an admin through a filter, say) still counts here.
		return array_slice( array_merge( array( $current ), $ids ), 0, self::MAX_SITES );
	}

	/**
	 * Can the capabilities saved for a site possibly make an administrator? Judged from the user's
	 * own meta, without switching. Only the core roles below administrator are ruled out.
	 *
	 * @param mixed $caps Value of the "{prefix}capabilities" meta.
	 */
	private static function may_be_admin( $caps ): bool {
		if ( ! is_array( $caps ) ) {
			return false;
		}
		foreach ( $caps as $name => $granted ) {
			if ( $granted && ! in_array( $name, array( 'subscriber', 'contributor', 'author', 'editor' ), true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Should recording wait for a second factor to pass?
	 *
	 * @param \WP_User $user   The user.
	 * @param string   $method Login method.
	 */
	private function defer_to_second_factor( \WP_User $user, string $method ): bool {
		// Two Factor ends the request at "wp_login" priority 10, so when this code runs for a user
		// who uses it, no challenge happened (single sign-on, magic link). Defer only if its handler runs after ours.
		$priority = class_exists( 'Two_Factor_Core', false ) ? has_action( 'wp_login', array( 'Two_Factor_Core', 'wp_login' ) ) : false;
		$defer    = is_int( $priority ) && $priority > 20 && is_callable( array( 'Two_Factor_Core', 'is_user_using_two_factor' ) )
			&& (bool) call_user_func( array( 'Two_Factor_Core', 'is_user_using_two_factor' ), $user->ID );
		/**
		 * Filters whether an interactive password login is held back until a second factor passes.
		 *
		 * Return true for a two-factor plugin that finishes the login after priority 20 of
		 * "wp_login", then fire the "wp_bouncer_record_admin_login" action with the WP_User
		 * once the second factor has passed. Nothing is recorded in between.
		 *
		 * @param bool     $defer  Default: the user uses the Two Factor plugin and its wp_login handler runs after priority 20.
		 * @param \WP_User $user   The user.
		 * @param string   $method Login method.
		 */
		return (bool) apply_filters( 'wp_bouncer_admin_login_defer', $defer, $user, $method );
	}

	/**
	 * Record one login on the current site (already switched to it).
	 *
	 * @param \WP_User          $user   The user.
	 * @param string            $method One of the LoginEvent::METHOD_* constants.
	 * @param array<int, mixed> $facts ip, range, country, reliable, request method, uri, user agent.
	 */
	private function record_on_site( \WP_User $user, string $method, array $facts ): void {
		list( $ip, $range, $country, $reliable, $req_method, $req_uri, $req_agent ) = $facts;
		$id = (int) $user->ID;

		$now    = time();
		$event  = new LoginEvent( $id, (string) $user->user_login, $ip, $range, $country, $method, $now );
		$repo   = new LoginHistoryRepository();
		$policy = new LoginLocationPolicy( $this->window_days() * DAY_IN_SECONDS );
		$a      = null;
		$note   = 'location not checked: client IP not reliable (check the IP source setting)';
		$alert  = 'none';
		if ( $reliable ) {
			$a    = $policy->assess( $repo->load( $id ), $range, $country, $now );
			$note = '';
			if ( $a->first ) {
				$note = 'first recorded login, location history started';
			} elseif ( $a->is_new_location() ) {
				$note = 'new location: IP range ' . $range . ( '' !== $country ? ', country ' . $country : '' );
				try {
					$alert = $this->plugin->alerts()->check_admin_login( $event, $a );
				} catch ( \Throwable $e ) {
					// A failing alert filter must not cost the Activity Log row, the history or the alert: fail open.
					$alert = 'send';
					$this->report( $e );
				}
				if ( 'throttled' === $alert ) {
					$note .= ' — alert throttled';
				}
			}
		}

		$row_id = $this->plugin->log_writer()->record(
			array(
				'ip'         => $ip,
				'country'    => $country,
				'rule'       => self::LOG_RULE,
				'action'     => BlockLogInterface::ACTION_LOGIN,
				'reason'     => $event->reason( $note ),
				'method'     => $req_method,
				'uri'        => $req_uri,
				'user_agent' => $req_agent,
			)
		);

		// Save the history first: a failure while queueing the alert must not make the next login alert again.
		if ( null !== $a ) {
			$repo->save( $id, $a->history );
		}
		if ( null !== $a && $a->is_new_location() ) {
			$this->plugin->alerts()->on_admin_login( $event, $a, $row_id > 0, $alert );
		}

		/**
		 * Fires after an administrator login was recorded.
		 *
		 * @param array $event Keys user_id, login, ip, range, country, method, time.
		 * @param array $flags Keys first, new_range, new_country, reliable.
		 */
		do_action(
			'wp_bouncer_admin_login_recorded',
			$event->to_array(),
			array(
				'first'       => null !== $a && $a->first,
				'new_range'   => null !== $a && $a->new_range,
				'new_country' => null !== $a && $a->new_country,
				'reliable'    => $reliable,
			)
		);
	}

	/**
	 * Is this user an administrator, judged now? Never asks about the current user.
	 *
	 * @param \WP_User $user The user.
	 */
	private function is_admin( \WP_User $user ): bool {
		$is_admin = is_super_admin( $user->ID ) || in_array( 'administrator', (array) $user->roles, true ) || $user->has_cap( 'manage_options' );
		/**
		 * Filters whether a user's logins are recorded as administrator logins.
		 *
		 * @param bool     $is_admin Default: super admin, administrator role or manage_options.
		 * @param \WP_User $user     The user.
		 */
		return (bool) apply_filters( 'wp_bouncer_admin_login_is_admin', $is_admin, $user );
	}

	/** Days a history entry is kept (30 to 365). */
	public static function window_days(): int {
		/**
		 * Filters how many days a login location stays in an administrator's history.
		 *
		 * @param int $days Default 90, clamped to 30-365.
		 */
		return max( 30, min( 365, (int) apply_filters( 'wp_bouncer_admin_login_window_days', 90 ) ) );
	}
}
