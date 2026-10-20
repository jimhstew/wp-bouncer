<?php
/**
 * Admin menu, screens and form handlers.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Alerts\AlertNotifier;
use WPBouncer\Geo\Countries;
use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Plugin;
use WPBouncer\Rules\CountryRule;
use WPBouncer\Rules\IpBlocklistRule;
use WPBouncer\Rules\NotFoundFloodRule;
use WPBouncer\Rules\RateLimitRule;
use WPBouncer\Rules\SensitiveFileRule;
use WPBouncer\Rules\UserAgentRule;
use WPBouncer\Settings;
use WPBouncer\Support\IpUtils;
use WPBouncer\Traffic\ClientClassifier;

defined( 'ABSPATH' ) || exit;

/**
 * One top-level "Bouncer" menu with tabs:
 *
 *   dashboard  At-a-glance stats and an on/off switch for every rule.
 *   general    Mode, IP detection, allowlist, retention, block message, geo source.
 *   rules      Settings for each rule.
 *   countries  Country picker.
 *   log        Searchable, filterable activity log with CSV export.
 *   traffic    Every request that reached WordPress (optional, kept up to a week).
 *   tools      Geo database import, unlock an IP.
 *
 * Every state-changing action posts to admin-post.php and is protected by a
 * nonce and the manage_options capability.
 */
final class AdminController {

	public const SLUG       = 'wp-bouncer';
	public const CAPABILITY = 'manage_options';

	private Plugin $plugin;

	/**
	 * @param Plugin $plugin Plugin instance.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/** Register admin hooks. */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_notices', array( $this, 'notices' ) );
		add_action( 'admin_post_wp_bouncer_save', array( $this, 'handle_save' ) );
		add_action( 'admin_post_wp_bouncer_toggle_rule', array( $this, 'handle_toggle_rule' ) );
		add_action( 'admin_post_wp_bouncer_block_ip', array( $this, 'handle_block_ip' ) );
		add_action( 'admin_post_wp_bouncer_unlock_ip', array( $this, 'handle_unlock_ip' ) );
		add_action( 'admin_post_wp_bouncer_clear_log', array( $this, 'handle_clear_log' ) );
		add_action( 'admin_post_wp_bouncer_export_log', array( $this, 'handle_export_log' ) );
		add_action( 'admin_post_wp_bouncer_clear_traffic', array( $this, 'handle_clear_traffic' ) );
		add_action( 'admin_post_wp_bouncer_export_traffic', array( $this, 'handle_export_traffic' ) );
		add_action( 'admin_post_wp_bouncer_geo_import', array( $this, 'handle_geo_import' ) );
		add_action( 'admin_post_wp_bouncer_geo_step', array( $this, 'handle_geo_step' ) );
		add_action( 'admin_post_wp_bouncer_geo_cancel', array( $this, 'handle_geo_cancel' ) );
		add_action( 'wp_ajax_wp_bouncer_geo_step', array( $this, 'ajax_geo_step' ) );
		add_action( 'admin_post_wp_bouncer_test_alert', array( $this, 'handle_test_alert' ) );
		add_action( 'admin_post_wp_bouncer_uploads_probe', array( $this, 'handle_uploads_probe' ) );
		add_action( 'admin_post_wp_bouncer_uploads_sync', array( $this, 'handle_uploads_sync' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( $this->plugin->file() ), array( $this, 'action_links' ) );
	}

	/* ------------------------------------------------------------------
	 * Labels shared by the views
	 * ---------------------------------------------------------------- */

	/**
	 * Rule id => [ title, one-line description ].
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function rule_labels(): array {
		return array(
			'ip_blocklist'     => array( __( 'IP blocklist', 'wp-bouncer' ), __( 'Refuse specific IP addresses and CIDR ranges.', 'wp-bouncer' ) ),
			'user_agent'       => array( __( 'User-Agent filter', 'wp-bouncer' ), __( 'Refuse known attack tools and requests with no User-Agent.', 'wp-bouncer' ) ),
			'country'          => array( __( 'Country blocking', 'wp-bouncer' ), __( 'Refuse (or only admit) visitors from chosen countries.', 'wp-bouncer' ) ),
			'xmlrpc'           => array( __( 'XML-RPC blocking', 'wp-bouncer' ), __( 'Close xmlrpc.php, a common brute-force and pingback-abuse target.', 'wp-bouncer' ) ),
			'login_lockout'    => array( __( 'Login lockout', 'wp-bouncer' ), __( 'Lock out IPs after repeated failed logins.', 'wp-bouncer' ) ),
			'rate_limit'       => array( __( 'Rate limiting', 'wp-bouncer' ), __( 'Temporarily ban IPs that make too many requests.', 'wp-bouncer' ) ),
			'waf'              => array( __( 'Web application firewall', 'wp-bouncer' ), __( 'Refuse SQL injection, XSS, path traversal and code injection payloads.', 'wp-bouncer' ) ),
			'user_enumeration' => array( __( 'User enumeration', 'wp-bouncer' ), __( 'Stop anonymous visitors from harvesting usernames.', 'wp-bouncer' ) ),
			'sensitive_files'  => array( __( 'Sensitive-file probes', 'wp-bouncer' ), __( 'Ban IPs that look for .env, .git, backups, database dumps and web shells.', 'wp-bouncer' ) ),
			'not_found'        => array( __( '404 flood', 'wp-bouncer' ), __( 'Ban IPs that hit many "not found" pages, as vulnerability scanners do.', 'wp-bouncer' ) ),
			'uploads_php'      => array( __( 'No PHP in uploads', 'wp-bouncer' ), __( 'Stop scripts running from the uploads folder, and refuse uploads that are scripts.', 'wp-bouncer' ) ),
		);
	}

	/**
	 * Everything that can appear in the log's Rule column: the rules plus
	 * email alerts (which have no on/off switch on the Dashboard).
	 *
	 * @return array<string, string> Id => title.
	 */
	public static function log_rule_labels(): array {
		$out = array();
		foreach ( self::rule_labels() as $id => $label ) {
			$out[ $id ] = $label[0];
		}
		$out[ AlertNotifier::LOG_RULE ] = __( 'Email alerts', 'wp-bouncer' );
		return $out;
	}

	/**
	 * Title for a rule id (falls back to the id for custom rules).
	 *
	 * @param string $id Rule id.
	 */
	public static function rule_title( string $id ): string {
		return self::log_rule_labels()[ $id ] ?? $id;
	}

	/**
	 * Label for a client type.
	 *
	 * @param string $type ClientClassifier constant.
	 */
	public static function client_label( string $type ): string {
		$labels = array(
			ClientClassifier::BROWSER       => __( 'Browser', 'wp-bouncer' ),
			ClientClassifier::MOBILE        => __( 'Mobile browser', 'wp-bouncer' ),
			ClientClassifier::SEARCH_ENGINE => __( 'Search engine', 'wp-bouncer' ),
			ClientClassifier::BOT           => __( 'Bot or crawler', 'wp-bouncer' ),
			ClientClassifier::MONITOR       => __( 'Uptime monitor', 'wp-bouncer' ),
			ClientClassifier::FEED          => __( 'Feed reader', 'wp-bouncer' ),
			ClientClassifier::WORDPRESS     => __( 'WordPress', 'wp-bouncer' ),
			ClientClassifier::TOOL          => __( 'Script or tool', 'wp-bouncer' ),
			ClientClassifier::SCANNER       => __( 'Attack tool', 'wp-bouncer' ),
			ClientClassifier::UNKNOWN       => __( 'No User-Agent', 'wp-bouncer' ),
			ClientClassifier::OTHER         => __( 'Other', 'wp-bouncer' ),
		);
		return $labels[ $type ] ?? $type;
	}

	/** @return array<string, string> Tab key => label. */
	public static function tabs(): array {
		return array(
			'dashboard' => __( 'Dashboard', 'wp-bouncer' ),
			'general'   => __( 'General', 'wp-bouncer' ),
			'rules'     => __( 'Rules', 'wp-bouncer' ),
			'countries' => __( 'Countries', 'wp-bouncer' ),
			'log'       => __( 'Activity Log', 'wp-bouncer' ),
			'traffic'   => __( 'Traffic', 'wp-bouncer' ),
			'tools'     => __( 'Tools', 'wp-bouncer' ),
		);
	}

	/* ------------------------------------------------------------------
	 * Menu, assets, notices
	 * ---------------------------------------------------------------- */

	/** Add the menu page. */
	public function add_menu(): void {
		add_menu_page(
			__( 'WP Bouncer', 'wp-bouncer' ),
			__( 'Bouncer', 'wp-bouncer' ),
			self::CAPABILITY,
			self::SLUG,
			array( $this, 'render' ),
			'dashicons-shield',
			80
		);
	}

	/**
	 * Load CSS/JS on our screen only.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue_assets( string $hook ): void {
		if ( 'toplevel_page_' . self::SLUG !== $hook ) {
			return;
		}
		$url = plugin_dir_url( $this->plugin->file() );
		wp_enqueue_style( 'wp-bouncer-admin', $url . 'assets/admin.css', array(), Plugin::VERSION );
		wp_enqueue_script( 'wp-bouncer-admin', $url . 'assets/admin.js', array(), Plugin::VERSION, true );
		wp_localize_script(
			'wp-bouncer-admin',
			'wpBouncer',
			array(
				'yourIp'   => $this->plugin->client_ip(),
				'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
				'geoNonce' => wp_create_nonce( 'wp_bouncer_geo_step' ),
				'toolsUrl' => self::url( 'tools' ),
				'i18n'     => array(
					/* translators: %d: number of selected countries. */
					'selected'    => __( '%d selected', 'wp-bouncer' ),
					/* translators: 1: percent done, 2: ranges loaded so far. */
					'geoProgress' => __( 'Importing: %1$s%% done, %2$s ranges loaded…', 'wp-bouncer' ),
					'geoFailed'   => __( 'The import stopped with an error:', 'wp-bouncer' ),
					'geoRetry'    => __( 'Retry', 'wp-bouncer' ),
				),
			)
		);
	}

	/** Configuration warnings shown on our screen. */
	public function notices(): void {
		// Shown on every admin screen: leaving the switch on leaves the site unprotected.
		if ( Plugin::is_disabled() && current_user_can( self::CAPABILITY ) ) {
			$this->notice( 'error', __( 'WP Bouncer is switched off by WP_BOUNCER_DISABLE in wp-config.php. Nothing is being blocked. Remove that line once the settings are fixed.', 'wp-bouncer' ) );
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'toplevel_page_' . self::SLUG !== $screen->id || ! current_user_can( self::CAPABILITY ) ) {
			return;
		}
		$s = $this->plugin->settings();

		if ( $s->is_monitor_mode() ) {
			$this->notice( 'warning', __( 'Monitor mode is on: matching requests are logged but NOT blocked.', 'wp-bouncer' ) );
		}
		if ( 'remote_addr' !== $s->get( 'ip_source' ) && empty( $s->get( 'trusted_proxies' ) ) ) {
			$this->notice( 'warning', __( 'You are reading the client IP from a proxy header with no trusted proxies listed. Anyone can forge that header. Add your proxy or CDN ranges under General → Trusted proxies.', 'wp-bouncer' ) );
		}
		$country = $s->rule( 'country' );
		$meta    = get_option( Plugin::GEO_META_OPTION, array() );
		if ( ! empty( $country['enabled'] ) && empty( $meta['rows'] ) && 'header' !== $s->get( 'geo_source' ) ) {
			$this->notice( 'error', __( 'Country blocking is on but no geo database is loaded, so it can\'t identify any country. Import one under Tools.', 'wp-bouncer' ) );
		}
		$uploads = get_option( UploadsGuard::STATE_OPTION );
		if ( UploadsGuard::is_broken() && $this->plugin->uploads_guard()->wants_htaccess() ) {
			$this->notice( 'error', __( 'WP Bouncer removed its block from wp-content/uploads/.htaccess: with it in place, your server answered uploaded files (images too) with an error, probably because it doesn\'t allow access rules in .htaccess. Uploads are not protected. See Rules → No PHP in uploads.', 'wp-bouncer' ) );
		} elseif ( $this->plugin->uploads_guard()->wants_htaccess() && is_array( $uploads ) && empty( $uploads['ok'] ) ) {
			$this->notice( 'warning', __( 'WP Bouncer could not write its block to wp-content/uploads/.htaccess (the folder may not be writable). See Rules → No PHP in uploads.', 'wp-bouncer' ) );
		}

		// phpcs:disable WordPress.Security.NonceVerification -- display only.
		if ( isset( $_GET['wpb_msg'] ) ) {
			$this->notice( isset( $_GET['wpb_err'] ) ? 'error' : 'success', sanitize_text_field( wp_unslash( $_GET['wpb_msg'] ) ) );
		}
		// phpcs:enable
	}

	/**
	 * Print a notice.
	 *
	 * @param string $type    success|warning|error|info.
	 * @param string $message Plain text.
	 */
	private function notice( string $type, string $message ): void {
		printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $type ), esc_html( $message ) );
	}

	/**
	 * "Settings" link on the Plugins screen.
	 *
	 * @param string[] $links Existing links.
	 * @return string[]
	 */
	public function action_links( array $links ): array {
		array_unshift( $links, sprintf( '<a href="%s">%s</a>', esc_url( self::url() ), esc_html__( 'Settings', 'wp-bouncer' ) ) );
		return $links;
	}

	/**
	 * URL of a tab.
	 *
	 * @param string               $tab  Tab key.
	 * @param array<string, mixed> $args Extra query args.
	 */
	public static function url( string $tab = 'dashboard', array $args = array() ): string {
		return add_query_arg( array_merge( array( 'page' => self::SLUG, 'tab' => $tab ), $args ), admin_url( 'admin.php' ) );
	}

	/* ------------------------------------------------------------------
	 * Rendering
	 * ---------------------------------------------------------------- */

	/** Render the current tab. */
	public function render(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'wp-bouncer' ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification -- navigation only.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'dashboard';
		if ( ! array_key_exists( $tab, self::tabs() ) ) {
			$tab = 'dashboard';
		}

		$plugin   = $this->plugin;
		$settings = $plugin->settings()->to_array();
		$view_dir = __DIR__ . '/views/';

		echo '<div class="wrap wp-bouncer">';
		require $view_dir . 'partials/header.php';
		require $view_dir . $tab . '.php';
		echo '</div>';
	}

	/* ------------------------------------------------------------------
	 * Form handlers (admin-post.php)
	 * ---------------------------------------------------------------- */

	/**
	 * Check capability and nonce, or die.
	 *
	 * @param string $action Nonce action.
	 */
	private function guard( string $action ): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'wp-bouncer' ), 403 );
		}
		check_admin_referer( $action );
	}

	/**
	 * Redirect back to a tab with a message.
	 *
	 * @param string $tab     Tab key.
	 * @param string $message Message.
	 * @param bool   $error   Show as an error.
	 * @return never
	 */
	private function back( string $tab, string $message, bool $error = false ): void {
		$args = array( 'wpb_msg' => rawurlencode( $message ) );
		if ( $error ) {
			$args['wpb_err'] = 1;
		}
		wp_safe_redirect( self::url( $tab, $args ) );
		exit;
	}

	/**
	 * Write settings and refresh the in-memory copy.
	 *
	 * @param array<string, mixed> $values Sanitised settings.
	 */
	private function save( array $values ): void {
		update_option( Settings::OPTION, $values, true );
		$this->plugin->reload_settings();
	}

	/** Save one settings tab. */
	public function handle_save(): void {
		$this->guard( 'wp_bouncer_save' );
		$tab = isset( $_POST['tab'] ) ? sanitize_key( wp_unslash( $_POST['tab'] ) ) : '';
		if ( ! isset( Settings::TAB_FIELDS[ $tab ] ) ) {
			$this->back( 'dashboard', __( 'Unknown settings section.', 'wp-bouncer' ), true );
		}
		// Raw input is sanitised field by field in Settings::sanitize().
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$input = isset( $_POST['wp_bouncer'] ) && is_array( $_POST['wp_bouncer'] ) ? wp_unslash( $_POST['wp_bouncer'] ) : array();

		$values  = Settings::apply_form( $this->plugin->settings()->to_array(), $input, $tab );
		$message = __( 'Settings saved.', 'wp-bouncer' );

		$self_block = $this->would_block_current_admin( $values );
		if ( null !== $self_block ) {
			$values['allowlist'][] = $this->plugin->client_ip();
			$values                = Settings::sanitize( $values );
			$message              .= ' ' . sprintf(
				/* translators: 1: IP address, 2: reason. */
				__( 'These settings would have blocked you (%2$s), so your IP %1$s was added to the allowlist.', 'wp-bouncer' ),
				$this->plugin->client_ip(),
				$self_block
			);
		}

		$this->save( $values );
		$this->back( $tab, $message );
	}

	/**
	 * Would the new settings refuse the admin who is saving them?
	 *
	 * Checks the rules that apply to every page (IP blocklist, country, User-Agent)
	 * against the admin's own request.
	 *
	 * @param array<string, mixed> $values Proposed settings.
	 * @return string|null The block reason, or null if the admin would get in.
	 */
	private function would_block_current_admin( array $values ): ?string {
		$request = $this->plugin->current_request();
		$ip      = $request->ip();
		if ( '' === $ip || IpUtils::is_loopback( $ip ) || IpUtils::matches_any( $ip, (array) $values['allowlist'] ) ) {
			return null;
		}
		$rules = array(
			new IpBlocklistRule( $values['rules']['ip_blocklist'] ),
			new CountryRule( $values['rules']['country'], $this->plugin->geo() ),
			new UserAgentRule( $values['rules']['user_agent'] ),
		);
		foreach ( $rules as $rule ) {
			$verdict = $rule->is_enabled() ? $rule->inspect( $request ) : null;
			if ( null !== $verdict ) {
				return $verdict->reason();
			}
		}
		return null;
	}

	/** Flip a single rule on or off from the dashboard. */
	public function handle_toggle_rule(): void {
		$this->guard( 'wp_bouncer_toggle_rule' );
		$id     = isset( $_POST['rule'] ) ? sanitize_key( wp_unslash( $_POST['rule'] ) ) : '';
		$values = $this->plugin->settings()->to_array();
		if ( ! isset( $values['rules'][ $id ] ) ) {
			$this->back( 'dashboard', __( 'Unknown rule.', 'wp-bouncer' ), true );
		}
		$values['rules'][ $id ]['enabled'] = empty( $values['rules'][ $id ]['enabled'] );
		$this->save( Settings::sanitize( $values ) );
		$this->back(
			'dashboard',
			sprintf(
				/* translators: 1: rule name, 2: "enabled" or "disabled". */
				__( '%1$s %2$s.', 'wp-bouncer' ),
				self::rule_title( $id ),
				$values['rules'][ $id ]['enabled'] ? __( 'enabled', 'wp-bouncer' ) : __( 'disabled', 'wp-bouncer' )
			)
		);
	}

	/** Add an IP to the blocklist (from the log or dashboard). */
	public function handle_block_ip(): void {
		$this->guard( 'wp_bouncer_block_ip' );
		$ip = isset( $_REQUEST['ip'] ) ? trim( sanitize_text_field( wp_unslash( $_REQUEST['ip'] ) ) ) : '';
		if ( ! IpUtils::is_valid_range( $ip ) ) {
			$this->back( 'log', __( 'That is not a valid IP address or range.', 'wp-bouncer' ), true );
		}
		$back = isset( $_REQUEST['back'] ) && 'traffic' === $_REQUEST['back'] ? 'traffic' : 'log';
		if ( IpUtils::in_range( $this->plugin->client_ip(), $ip ) ) {
			$this->back( $back, __( 'Refusing to block your own IP address.', 'wp-bouncer' ), true );
		}
		$values                                   = $this->plugin->settings()->to_array();
		$values['rules']['ip_blocklist']['ips'][] = $ip;
		$values['rules']['ip_blocklist']['enabled'] = true;
		$this->save( Settings::sanitize( $values ) );
		/* translators: %s: IP address. */
		$this->back( $back, sprintf( __( '%s added to the IP blocklist.', 'wp-bouncer' ), $ip ) );
	}

	/** Lift login lockouts and every temporary ban for an IP. */
	public function handle_unlock_ip(): void {
		$this->guard( 'wp_bouncer_unlock_ip' );
		$ip = isset( $_POST['ip'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['ip'] ) ) ) : '';
		if ( ! IpUtils::is_valid( $ip ) ) {
			$this->back( 'tools', __( 'That is not a valid IP address.', 'wp-bouncer' ), true );
		}
		$this->plugin->login_guard()->clear( $ip );
		$this->plugin->store()->delete( RateLimitRule::ban_key( $ip ) );
		$this->plugin->store()->delete( RateLimitRule::counter_key( $ip ) );
		$this->plugin->store()->delete( SensitiveFileRule::ban_key( $ip ) );
		$this->plugin->store()->delete( NotFoundFloodRule::ban_key( $ip ) );
		$this->plugin->store()->delete( NotFoundFloodRule::counter_key( $ip ) );
		/* translators: %s: IP address. */
		$this->back( 'tools', sprintf( __( 'Lockouts and bans cleared for %s.', 'wp-bouncer' ), $ip ) );
	}

	/** Send a test alert email. */
	public function handle_test_alert(): void {
		$this->guard( 'wp_bouncer_test_alert' );
		$result = $this->plugin->alerts()->send_test();
		if ( true !== $result ) {
			/* translators: %s: error message. */
			$this->back( 'general', sprintf( __( 'The test email was not sent: %s', 'wp-bouncer' ), $result ), true );
		}
		$this->back(
			'general',
			sprintf(
				/* translators: %s: email addresses. */
				__( 'Test email sent to %s. If it does not arrive, check spam, then your site\'s mail setup.', 'wp-bouncer' ),
				implode( ', ', $this->plugin->alerts()->recipients() )
			)
		);
	}

	/** Check whether the server runs PHP from the uploads folder. */
	public function handle_uploads_probe(): void {
		$this->guard( 'wp_bouncer_uploads_probe' );
		$result = $this->plugin->uploads_guard()->probe();
		$this->back( 'rules', self::probe_message( $result['result'] ), in_array( $result['result'], array( 'unprotected', 'broken' ), true ) );
	}

	/** Write (or remove) the uploads/.htaccess block now. */
	public function handle_uploads_sync(): void {
		$this->guard( 'wp_bouncer_uploads_sync' );
		$guard = $this->plugin->uploads_guard();
		delete_option( UploadsGuard::STATE_OPTION );
		$guard->maybe_sync();
		$state = get_option( UploadsGuard::STATE_OPTION );
		if ( empty( $state['ok'] ) ) {
			$this->back( 'rules', __( 'Could not update wp-content/uploads/.htaccess. Check that the folder is writable, or add the rule to your server config by hand.', 'wp-bouncer' ), true );
		}
		$this->back( 'rules', $guard->wants_htaccess() ? __( 'The block is in wp-content/uploads/.htaccess.', 'wp-bouncer' ) : __( 'The block was removed from wp-content/uploads/.htaccess.', 'wp-bouncer' ) );
	}

	/**
	 * Explain an uploads test result.
	 *
	 * @param string $result protected|unprotected|unknown.
	 */
	public static function probe_message( string $result ): string {
		switch ( $result ) {
			case 'protected':
				return __( 'Protected: the server refused to run a test script placed in the uploads folder.', 'wp-bouncer' );
			case 'unprotected':
				return __( 'Not protected: the server ran a test script from the uploads folder. On nginx, add the rule shown below to your server config.', 'wp-bouncer' );
			case 'broken':
				return __( 'Not protected: with the .htaccess block in place, your server answered uploaded files with an error (it probably doesn\'t allow access rules in .htaccess), so WP Bouncer removed the block. Ask your host to allow "AllowOverride AuthConfig Limit" for the site, or add the rule to the server config, then click "Write it now".', 'wp-bouncer' );
			default:
				return __( 'Could not tell: the test script could not be fetched (the site may not be able to reach itself). The details are below.', 'wp-bouncer' );
		}
	}

	/** Empty the activity log. */
	public function handle_clear_log(): void {
		$this->guard( 'wp_bouncer_clear_log' );
		$this->plugin->log()->clear();
		$this->back( 'log', __( 'Activity log cleared.', 'wp-bouncer' ) );
	}

	/** Download the (filtered) log as CSV. */
	public function handle_export_log(): void {
		$this->guard( 'wp_bouncer_export_log' );
		$filters = self::log_filters_from_request();

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="wp-bouncer-log-' . gmdate( 'Ymd-His' ) . '.csv"' );

		$out = fopen( 'php://output', 'w' );
		fputcsv( $out, array( 'time_utc', 'ip', 'country', 'rule', 'action', 'reason', 'method', 'uri', 'user_agent' ) );
		for ( $page = 1; $page <= 100; $page++ ) {
			$rows = $this->plugin->log()->query( $filters, 1000, $page );
			foreach ( $rows as $row ) {
				fputcsv(
					$out,
					array_map(
						array( self::class, 'csv_safe' ),
						array( $row['created_at'], $row['ip'], $row['country'], $row['rule'], $row['action'], $row['reason'], $row['method'], $row['uri'], $row['user_agent'] )
					)
				);
			}
			if ( count( $rows ) < 1000 ) {
				break;
			}
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}

	/** Empty the traffic log. */
	public function handle_clear_traffic(): void {
		$this->guard( 'wp_bouncer_clear_traffic' );
		$this->plugin->traffic_log()->clear();
		$this->back( 'traffic', __( 'Traffic log cleared.', 'wp-bouncer' ) );
	}

	/** Download the (filtered) traffic log as CSV. */
	public function handle_export_traffic(): void {
		$this->guard( 'wp_bouncer_export_traffic' );
		$filters = self::traffic_filters_from_request();

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="wp-bouncer-traffic-' . gmdate( 'Ymd-His' ) . '.csv"' );

		$out = fopen( 'php://output', 'w' );
		fputcsv( $out, array( 'time_utc', 'ip', 'client', 'method', 'url', 'status', 'referrer', 'user_agent', 'user_id' ) );
		for ( $page = 1; $page <= 500; $page++ ) {
			$rows = $this->plugin->traffic_log()->query( $filters, 1000, $page );
			foreach ( $rows as $row ) {
				fputcsv(
					$out,
					array_map(
						array( self::class, 'csv_safe' ),
						array( $row['created_at'], $row['ip'], $row['client'], $row['method'], $row['uri'], $row['status'], $row['referrer'], $row['user_agent'], $row['user_id'] )
					)
				);
			}
			if ( count( $rows ) < 1000 ) {
				break;
			}
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}

	/**
	 * Traffic filters from the query string.
	 *
	 * @return array<string, string>
	 */
	public static function traffic_filters_from_request(): array {
		// phpcs:disable WordPress.Security.NonceVerification -- read-only filters.
		$filters = array();
		$client  = isset( $_REQUEST['client'] ) ? sanitize_key( wp_unslash( $_REQUEST['client'] ) ) : '';
		if ( in_array( $client, ClientClassifier::types(), true ) ) {
			$filters['client'] = $client;
		}
		$status = isset( $_REQUEST['status'] ) ? sanitize_key( wp_unslash( $_REQUEST['status'] ) ) : '';
		if ( preg_match( '/^[1-5]xx$/', $status ) ) {
			$filters['status'] = $status;
		}
		$ip = isset( $_REQUEST['ip'] ) ? trim( sanitize_text_field( wp_unslash( $_REQUEST['ip'] ) ) ) : '';
		if ( IpUtils::is_valid( $ip ) ) {
			$filters['ip'] = $ip;
		}
		if ( ! empty( $_REQUEST['s'] ) ) {
			$filters['search'] = sanitize_text_field( wp_unslash( $_REQUEST['s'] ) );
		}
		// phpcs:enable
		return $filters;
	}

	/**
	 * Traffic filters back to query args.
	 *
	 * @param array<string, string> $filters Filters.
	 * @return array<string, string>
	 */
	public static function traffic_filters_to_args( array $filters ): array {
		$args = array();
		foreach ( array( 'client' => 'client', 'status' => 'status', 'ip' => 'ip', 'search' => 's' ) as $key => $param ) {
			if ( ! empty( $filters[ $key ] ) ) {
				$args[ $param ] = rawurlencode( $filters[ $key ] );
			}
		}
		return $args;
	}

	/**
	 * Stop spreadsheet formula injection: attacker-controlled cells (URI, User-Agent)
	 * that start with = + - @ are prefixed with an apostrophe.
	 *
	 * @param mixed $value Cell value.
	 */
	public static function csv_safe( $value ): string {
		$value = (string) $value;
		return ( '' !== $value && false !== strpos( "=+-@\t\r", $value[0] ) ) ? "'" . $value : $value;
	}

	/**
	 * Log filters from the query string.
	 *
	 * @return array<string, string>
	 */
	public static function log_filters_from_request(): array {
		// phpcs:disable WordPress.Security.NonceVerification -- read-only filters.
		// Request param => log column. "log_action" avoids clashing with admin-post's "action".
		$filters = array();
		foreach ( array( 'rule' => 'rule', 'log_action' => 'action', 'country' => 'country' ) as $param => $column ) {
			if ( ! empty( $_REQUEST[ $param ] ) ) {
				$filters[ $column ] = sanitize_key( wp_unslash( $_REQUEST[ $param ] ) );
			}
		}
		if ( isset( $filters['country'] ) ) {
			$filters['country'] = strtoupper( $filters['country'] );
		}
		if ( ! empty( $_REQUEST['s'] ) ) {
			$filters['search'] = sanitize_text_field( wp_unslash( $_REQUEST['s'] ) );
		}
		// phpcs:enable
		return $filters;
	}

	/**
	 * Turn log filters back into query args (inverse of log_filters_from_request()).
	 *
	 * @param array<string, string> $filters Filters.
	 * @return array<string, string>
	 */
	public static function log_filters_to_args( array $filters ): array {
		$map  = array( 'rule' => 'rule', 'action' => 'log_action', 'country' => 'country', 'search' => 's' );
		$args = array();
		foreach ( $map as $column => $param ) {
			if ( ! empty( $filters[ $column ] ) ) {
				$args[ $param ] = rawurlencode( $filters[ $column ] );
			}
		}
		return $args;
	}

	/**
	 * Seconds of importing per request. Short enough for hosts that stop PHP
	 * after 30 seconds, including slow shared databases.
	 */
	private static function geo_step_seconds(): float {
		/**
		 * Filters how long each geo import step runs, in seconds.
		 *
		 * @param float $seconds Default 5.
		 */
		return max( 0.0, (float) apply_filters( 'wp_bouncer_geo_step_seconds', 5.0 ) );
	}

	/**
	 * Start a geo import from an upload or a URL.
	 *
	 * This request only fetches, unpacks and checks the file. The rows are
	 * loaded by later step requests (see GeoImport), so no request runs long.
	 */
	public function handle_geo_import(): void {
		// A body over post_max_size reaches PHP empty, nonce and all. The form
		// repeats the action in its URL so we still get here and can say why.
		if ( empty( $_POST ) && ! empty( $_SERVER['CONTENT_LENGTH'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			$this->back( 'tools', self::upload_error_message( UPLOAD_ERR_INI_SIZE ), true );
		}
		$this->guard( 'wp_bouncer_geo_import' );

		$file   = isset( $_FILES['geo_file'] ) && is_array( $_FILES['geo_file'] ) ? $_FILES['geo_file'] : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$upload = (int) ( $file['error'] ?? UPLOAD_ERR_NO_FILE );

		$path    = '';
		$cleanup = false;
		$source  = '';

		if ( UPLOAD_ERR_NO_FILE !== $upload ) {
			if ( UPLOAD_ERR_OK !== $upload ) {
				$this->back( 'tools', self::upload_error_message( $upload ), true );
			}
			$name = sanitize_file_name( wp_unslash( (string) ( $file['name'] ?? 'upload.csv' ) ) );
			if ( ! preg_match( '/\.(csv|csv\.gz|gz)$/i', $name ) ) {
				$this->back( 'tools', __( 'Please upload a .csv or .csv.gz file.', 'wp-bouncer' ), true );
			}
			if ( empty( $file['tmp_name'] ) || ! is_uploaded_file( $file['tmp_name'] ) ) {
				$this->back( 'tools', __( 'The upload did not arrive. Try again, or import by URL.', 'wp-bouncer' ), true );
			}
			$path   = (string) $file['tmp_name'];
			$source = $name;
		} elseif ( ! empty( $_POST['geo_url'] ) ) {
			$url = esc_url_raw( wp_unslash( $_POST['geo_url'] ) );
			if ( ! wp_http_validate_url( $url ) ) {
				$this->back( 'tools', __( 'That URL is not valid.', 'wp-bouncer' ), true );
			}
			require_once ABSPATH . 'wp-admin/includes/file.php';
			$tmp = download_url( $url, 120 );
			if ( is_wp_error( $tmp ) ) {
				/* translators: %s: error message. */
				$this->back( 'tools', sprintf( __( 'Download failed: %s', 'wp-bouncer' ), $tmp->get_error_message() ), true );
			}
			$path    = $tmp;
			$cleanup = true;
			$source  = $url;
		} else {
			$this->back( 'tools', __( 'Choose a file or enter a URL.', 'wp-bouncer' ), true );
		}

		$error = '';
		try {
			$this->plugin->geo_import()->start( $path, $source );
		} catch ( \Throwable $e ) {
			$error = $e->getMessage();
		} finally {
			if ( $cleanup ) {
				wp_delete_file( $path );
			}
		}
		if ( '' !== $error ) {
			$this->back( 'tools', $error, true );
		}

		// The Tools screen sees the running import and carries on with it.
		wp_safe_redirect( self::url( 'tools' ) );
		exit;
	}

	/**
	 * Explain a PHP upload error code.
	 *
	 * @param int $code UPLOAD_ERR_* value.
	 */
	public static function upload_error_message( int $code ): string {
		switch ( $code ) {
			case UPLOAD_ERR_INI_SIZE:
			case UPLOAD_ERR_FORM_SIZE:
				return sprintf(
					/* translators: %s: size limit such as "8 MB". */
					__( 'That file is larger than this server accepts (%s). Upload the .csv.gz instead of the unpacked .csv, or import by URL.', 'wp-bouncer' ),
					size_format( wp_max_upload_size() )
				);
			case UPLOAD_ERR_PARTIAL:
				return __( 'The upload was interrupted. Try again.', 'wp-bouncer' );
			default:
				/* translators: %d: PHP upload error code. */
				return sprintf( __( 'The server could not store the upload (PHP upload error %d).', 'wp-bouncer' ), $code );
		}
	}

	/** Run one import step over AJAX and report progress as JSON. */
	public function ajax_geo_step(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission to do that.', 'wp-bouncer' ) ), 403 );
		}
		check_ajax_referer( 'wp_bouncer_geo_step' );
		try {
			$progress = $this->plugin->geo_import()->step( self::geo_step_seconds() );
		} catch ( \Throwable $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
		if ( $progress['done'] ) {
			$progress['message'] = self::geo_done_message( $progress );
		}
		wp_send_json_success( $progress );
	}

	/** Run one import step without JavaScript, then return to the Tools tab. */
	public function handle_geo_step(): void {
		$this->guard( 'wp_bouncer_geo_step' );
		try {
			$progress = $this->plugin->geo_import()->step( self::geo_step_seconds() );
		} catch ( \Throwable $e ) {
			$this->back( 'tools', $e->getMessage(), true );
		}
		if ( $progress['done'] ) {
			$this->back( 'tools', self::geo_done_message( $progress ) );
		}
		wp_safe_redirect( self::url( 'tools' ) );
		exit;
	}

	/** Stop a running import, keeping what has loaded. */
	public function handle_geo_cancel(): void {
		$this->guard( 'wp_bouncer_geo_cancel' );
		$this->plugin->geo_import()->cancel();
		$this->back( 'tools', __( 'Import stopped. The ranges loaded so far are in use; import again for complete data.', 'wp-bouncer' ), true );
	}

	/**
	 * Success message for a finished import.
	 *
	 * @param array{imported: int, skipped: int} $progress Final counts.
	 */
	private static function geo_done_message( array $progress ): string {
		return sprintf(
			/* translators: 1: rows imported, 2: rows skipped. */
			__( 'Geo database imported: %1$s ranges loaded, %2$s lines skipped.', 'wp-bouncer' ),
			number_format_i18n( $progress['imported'] ),
			number_format_i18n( $progress['skipped'] )
		);
	}

	/* ------------------------------------------------------------------
	 * View helpers
	 * ---------------------------------------------------------------- */

	/**
	 * Output an on/off switch for a rule's "enabled" flag.
	 *
	 * @param string $id      Rule id.
	 * @param bool   $checked Current state.
	 */
	public static function rule_switch( string $id, bool $checked ): void {
		printf(
			'<label class="wpb-switch"><input type="checkbox" name="wp_bouncer[rules][%1$s][enabled]" value="1" %2$s><span class="wpb-slider" aria-hidden="true"></span><span class="screen-reader-text">%3$s</span></label>',
			esc_attr( $id ),
			checked( $checked, true, false ),
			esc_html__( 'Enabled', 'wp-bouncer' )
		);
	}

	/**
	 * Flag emoji for a country code (regional indicator symbols).
	 *
	 * @param string $code ISO alpha-2 code.
	 */
	public static function flag( string $code ): string {
		if ( ! preg_match( '/^[A-Z]{2}$/', $code ) || ! isset( Countries::all()[ $code ] ) || isset( Countries::SPECIAL[ $code ] ) ) {
			return '';
		}
		$out = '';
		foreach ( str_split( $code ) as $char ) {
			$out .= html_entity_decode( '&#' . ( 127397 + ord( $char ) ) . ';', ENT_NOQUOTES, 'UTF-8' );
		}
		return $out;
	}

	/**
	 * Action label for the log.
	 *
	 * @param string $action Action constant.
	 */
	public static function action_label( string $action ): string {
		switch ( $action ) {
			case BlockLogInterface::ACTION_MONITORED:
				return __( 'Monitored', 'wp-bouncer' );
			case BlockLogInterface::ACTION_LOCKOUT:
				return __( 'Lockout', 'wp-bouncer' );
			case BlockLogInterface::ACTION_ALERT:
				return __( 'Alert', 'wp-bouncer' );
			default:
				return __( 'Blocked', 'wp-bouncer' );
		}
	}
}
