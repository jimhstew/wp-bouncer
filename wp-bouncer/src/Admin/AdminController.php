<?php
/**
 * Admin menu, screens and form handlers.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Alerts\AlertNotifier;
use WPBouncer\Firewall\Firewall;
use WPBouncer\Firewall\IpResolver;
use WPBouncer\Firewall\Request;
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
use WPBouncer\SettingsDiff;
use WPBouncer\Support\CsvSanitizer;
use WPBouncer\Support\CounterSubject;
use WPBouncer\Support\IpUtils;
use WPBouncer\Traffic\ClientClassifier;

defined( 'ABSPATH' ) || exit;

/**
 * One top-level "Bouncer" menu with tabs:
 *
 *   Dashboard  At-a-glance stats and an on/off switch for every rule.
 *   General    Mode, IP detection, allowlist, retention, block message, geo source.
 *   Rules      Settings for each rule.
 *   Countries  Country picker.
 *   Log        Searchable, filterable activity log with CSV export.
 *   Traffic    Every request that reached WordPress (optional, kept up to a week).
 *   Tools      Geo database import, unlock an IP.
 *
 * Every state-changing action posts to admin-post.php and is protected by a
 * nonce and the manage_options capability.
 */
final class AdminController {

	public const SLUG       = 'wp-bouncer';
	public const CAPABILITY = 'manage_options';

	/** Rule name on the Activity Log rows written by the configuration audit. */
	public const SETTINGS_LOG_RULE = 'settings';

	/** Capability for server-wide actions (network admins on multisite). */
	public const FIREWALL_CAPABILITY = FirewallCapability::NAME;

	/**
	 * Plugin instance.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Rule overview (built on first use).
	 *
	 * @var RuleOverview|null
	 */
	private ?RuleOverview $overview = null;

	/**
	 * Set up the AdminController.
	 *
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
		add_action( 'admin_post_wp_bouncer_ip_setup', array( $this, 'handle_ip_setup' ) );
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

	/*
	 * ------------------------------------------------------------------
	 * Labels shared by the views
	 * ----------------------------------------------------------------
	 */

	/**
	 * Rule id => [ title, one-line description ].
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function rule_labels(): array {
		return RuleLabels::rules();
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
		$out[ self::SETTINGS_LOG_RULE ] = __( 'Settings changes', 'wp-bouncer' );
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

	/**
	 * List the admin tabs.
	 *
	 * @return array<string, string> Tab key => label.
	 */
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

	/*
	 * ------------------------------------------------------------------
	 * Menu, assets, notices
	 * ----------------------------------------------------------------
	 */

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
					'on'          => __( 'On', 'wp-bouncer' ),
					'off'         => __( 'Off', 'wp-bouncer' ),
					'notSaved'    => __( '(not saved)', 'wp-bouncer' ),
					'unsaved'     => __( 'You have unsaved changes.', 'wp-bouncer' ),
					'expandAll'   => __( 'Expand all settings', 'wp-bouncer' ),
					'collapseAll' => __( 'Collapse all settings', 'wp-bouncer' ),
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
		// One source of truth with the Rules and Dashboard tabs: RuleStatus decides, RuleLabels words it.
		$statuses = $this->overview()->statuses();
		foreach ( array_merge( $statuses['country']['reasons'], $statuses['uploads_php']['reasons'] ) as $reason ) {
			$text = RuleLabels::notice( $reason );
			if ( null !== $text ) {
				$this->notice( $text['type'], $text['text'], $text['link_url'], $text['link_text'] );
			}
		}

		// phpcs:disable WordPress.Security.NonceVerification -- display-only: the value is a code looked up in MessageCodes; no free text is shown and no state changes.
		$query               = array_filter( wp_unslash( $_GET ), 'is_string' );
		list( $code, $args ) = MessageCodes::from_query( $query );
		$is_error            = isset( $query['wpb_err'] );
		// phpcs:enable WordPress.Security.NonceVerification
		if ( '' !== $code ) {
			if ( MessageCodes::uses_detail( $code ) ) {
				$args['detail'] = MessageCodes::take_flash();
			}
			$text = MessageCodes::text( $code, $args );
			if ( null !== $text ) {
				$this->notice( $is_error ? 'error' : 'success', $text );
			}
		}
	}

	/**
	 * Print a notice.
	 *
	 * Errors and warnings use role="alert", the rest role="status".
	 *
	 * @param string $type      success|warning|error|info.
	 * @param string $message   Plain text.
	 * @param string $link_url  Optional link target.
	 * @param string $link_text Link text (needed with the URL).
	 */
	private function notice( string $type, string $message, string $link_url = '', string $link_text = '' ): void {
		$role = in_array( $type, array( 'error', 'warning' ), true ) ? 'alert' : 'status';
		$link = '' !== $link_url && '' !== $link_text
			? ' <a href="' . esc_url( $link_url ) . '">' . esc_html( $link_text ) . '</a>'
			: '';
		printf( '<div class="notice notice-%1$s is-dismissible" role="%2$s"><p>%3$s%4$s</p></div>', esc_attr( $type ), esc_attr( $role ), esc_html( $message ), $link ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $link is built from esc_url() and esc_html() above.
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
		return add_query_arg(
			array_merge(
				array(
					'page' => self::SLUG,
					'tab'  => $tab,
				),
				$args
			),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * URL of a rule on the screen where it is configured.
	 *
	 * Built-in rules open their settings on the Rules tab (the wpb_rule argument makes the server render
	 * that panel open). Country blocking is configured on the Countries tab.
	 *
	 * @param string $id Rule id.
	 */
	public static function rule_url( string $id ): string {
		if ( 'country' === $id ) {
			return self::url( 'countries' );
		}
		if ( ! RuleCatalog::is_builtin( $id ) ) {
			return self::url( 'rules' );
		}
		return self::url( 'rules', array( 'wpb_rule' => $id ) ) . '#rule-' . $id;
	}

	/** The grouped rule overview, shared by the notices and the Rules and Dashboard tabs. */
	private function overview(): RuleOverview {
		$this->overview ??= new RuleOverview( $this->plugin );
		return $this->overview;
	}

	/*
	 * ------------------------------------------------------------------
	 * Rendering
	 * ----------------------------------------------------------------
	 */

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
		$overview = $this->overview();
		$view_dir = __DIR__ . '/views/';

		echo '<div class="wrap wp-bouncer">';
		require $view_dir . 'partials/header.php';
		require $view_dir . $tab . '.php';
		echo '</div>';
	}

	/*
	 * ------------------------------------------------------------------
	 * Form handlers (admin-post.php)
	 * ----------------------------------------------------------------
	 */

	/**
	 * Check capability and nonce, or die.
	 *
	 * @param string $action Nonce action.
	 * @param string $cap    Capability required (wpb_manage_firewall for server-wide actions).
	 */
	private function guard( string $action, string $cap = self::CAPABILITY ): void {
		if ( ! current_user_can( $cap ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'wp-bouncer' ), 403 );
		}
		check_admin_referer( $action );
	}

	/**
	 * Redirect back to a tab with a message code.
	 *
	 * @param string               $tab      Tab key.
	 * @param string               $code     MessageCodes code.
	 * @param array<string, mixed> $args     Message arguments (a "detail" string is kept server-side, not in the URL).
	 * @param bool                 $error    Show as an error.
	 * @param string               $fragment Optional anchor on the tab, without the "#".
	 * @return never
	 */
	private function back( string $tab, string $code, array $args = array(), bool $error = false, string $fragment = '' ): void {
		if ( isset( $args['detail'] ) ) {
			MessageCodes::flash( (string) $args['detail'] );
		}
		$query = MessageCodes::to_query( $code, $args );
		if ( $error ) {
			$query['wpb_err'] = 1;
		}
		$fragment = sanitize_key( $fragment );
		// Landing on a rule's row also opens its settings (the result of what was just done is in there).
		if ( 0 === strpos( $fragment, 'rule-' ) && RuleCatalog::is_builtin( substr( $fragment, 5 ) ) ) {
			$query['wpb_rule'] = substr( $fragment, 5 );
		}
		$url = self::url( $tab, $query );
		wp_safe_redirect( '' !== $fragment ? $url . '#' . $fragment : $url );
		exit;
	}

	/**
	 * Write settings and refresh the in-memory copy.
	 *
	 * @param array<string, mixed> $values Sanitised settings.
	 */
	private function save( array $values ): void {
		if ( ! current_user_can( self::FIREWALL_CAPABILITY ) ) {
			// Sub-site admins on multisite can't change the .htaccess setting or add regex patterns.
			$values = Settings::preserve_privileged( $this->plugin->settings()->to_array(), $values );
		}
		$old = $this->plugin->settings()->to_array();
		update_option( Settings::OPTION, $values, true );
		// Audit BEFORE the new settings load: the request's IP and country, who gets the
		// alert, and whether alerts are on all come from the settings in force until now.
		$changes = $this->audit( $old, $values );
		$this->plugin->reload_settings();
		if ( ! empty( $changes ) ) {
			/**
			 * Fires after the settings were saved and something changed.
			 *
			 * @param string[]             $changes Changed key paths, such as "rules.xmlrpc.enabled" (lists count as one path).
			 * @param array<string, mixed> $old     Settings before.
			 * @param array<string, mixed> $new     Settings after.
			 */
			do_action( 'wp_bouncer_settings_changed', $changes, $old, $values );
		}
	}

	/**
	 * Configuration audit: record and alert on a settings change.
	 *
	 * Writes one "alert" row (rule "settings") naming the acting user and the
	 * changed key paths, never the values. Risky changes also queue a
	 * firewall_changes email. Nothing happens when nothing changed.
	 *
	 * @param array<string, mixed> $before Settings before the save.
	 * @param array<string, mixed> $after  Settings as saved.
	 * @return string[] The changed key paths.
	 */
	private function audit( array $before, array $after ): array {
		$changes = SettingsDiff::changes( $before, $after );
		if ( empty( $changes ) ) {
			return array();
		}
		$risky = SettingsDiff::risky( $changes, $before, $after );
		$this->write_audit_row( SettingsDiff::describe( $this->actor(), $changes, $risky ) );
		if ( ! empty( $risky ) ) {
			$this->plugin->alerts()->on_risky_settings_change( $risky, $changes, $after );
		}
		return $changes;
	}

	/** Login of the signed-in user, for audit rows. */
	private function actor(): string {
		$user = wp_get_current_user();
		return $user->exists() ? $user->user_login : 'unknown';
	}

	/**
	 * Write one audit row (alert action, rule "settings") for the current request.
	 *
	 * @param string $reason What happened and who did it; no setting values.
	 */
	private function write_audit_row( string $reason ): void {
		$request = $this->plugin->current_request();
		$this->plugin->log_writer()->record(
			array(
				'ip'         => $request->ip(),
				'country'    => (string) $this->plugin->geo()->lookup( $request->ip() ),
				'rule'       => self::SETTINGS_LOG_RULE,
				'action'     => BlockLogInterface::ACTION_ALERT,
				'reason'     => mb_strimwidth( $reason, 0, 255, '...' ),
				'method'     => $request->method(),
				'uri'        => $request->uri(),
				'user_agent' => $request->user_agent(),
			)
		);
	}

	/** Save one settings tab. */
	public function handle_save(): void {
		$this->guard( 'wp_bouncer_save' );
		$tab = isset( $_POST['tab'] ) ? sanitize_key( wp_unslash( $_POST['tab'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce and capability checked in $this->guard() at the top of this handler.
		if ( ! isset( Settings::TAB_FIELDS[ $tab ] ) ) {
			$this->back( 'dashboard', 'unknown_section', array(), true );
		}
		// Raw input is sanitised field by field in Settings::sanitize().
		$input = isset( $_POST['wp_bouncer'] ) && is_array( $_POST['wp_bouncer'] ) ? wp_unslash( $_POST['wp_bouncer'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Missing -- sanitised field by field in Settings::sanitize(); nonce and capability checked in $this->guard() at the top of this handler.

		$values  = Settings::apply_form( $this->plugin->settings()->to_array(), $input, $tab );
		$message = array();

		if ( 'general' === $tab ) {
			$dropped = Settings::dropped_broad_ranges( $input );
			if ( ! empty( $dropped ) ) {
				$message['dropped'] = implode( ',', $dropped );
			}
			if ( 'remote_addr' !== $values['ip_source'] && empty( $values['trusted_proxies'] ) ) {
				$message['noproxy'] = 1;
			}
		}

		// Test against the request as the NEW settings would see it: saving can change the IP source or proxies.
		list( $request, $allowlistable ) = $this->request_under( $values );
		$self_block                      = $this->would_block_current_admin( $values, $request );
		if ( null !== $self_block ) {
			// An address shared by many visitors (fallback, loopback or proxy) must never
			// be allowlisted: that would exempt everyone behind it. Refuse instead.
			if ( ! $allowlistable ) {
				$this->back( $tab, 'shared_refusal', array( 'detail' => $self_block ), true );
			}
			$values['allowlist'][] = $request->ip();
			$values                = Settings::sanitize( $values );
			$message['allow']      = $request->ip();
			$message['detail']     = $self_block;
		}

		$this->save( $values );
		$this->back( $tab, 'saved', $message );
	}

	/**
	 * One-click fixes offered by the IP setup notice (SetupNotices).
	 *
	 * "trust_peer" lists the address this request came from as a trusted proxy
	 * (and optionally switches the IP source to a header). "use_remote_addr"
	 * switches to the connection address. Capability and nonce are checked in
	 * guard(); the settings go through the normal sanitiser.
	 */
	public function handle_ip_setup(): void {
		$this->guard( SetupNotices::NONCE_ACTION );
		$fix    = isset( $_POST['fix'] ) ? sanitize_key( wp_unslash( $_POST['fix'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce and capability checked in $this->guard() at the top of this handler.
		$header = isset( $_POST['header'] ) ? sanitize_key( wp_unslash( $_POST['header'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce and capability checked in $this->guard() at the top of this handler.
		$values = $this->plugin->settings()->to_array();

		if ( 'use_remote_addr' === $fix ) {
			$values['ip_source'] = 'remote_addr';
			$values              = Settings::sanitize( $values );
			$message             = $this->guard_new_ip_settings( $values );
			$this->save( $values );
			$this->back( 'general', 'remote_addr_set', $message );
		}

		if ( 'trust_peer' === $fix ) {
			$peer = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '';
			if ( '' !== $header && ( 'remote_addr' === $header || ! isset( IpResolver::SOURCES[ $header ] ) ) ) {
				$this->back( 'general', 'unknown_header', array(), true );
			}
			$source = '' !== $header ? $header : (string) $values['ip_source'];
			if ( ! IpUtils::is_valid( $peer ) || 'remote_addr' === $source ) {
				$this->back( 'general', 'proxy_unknown', array(), true );
			}
			// The notice posts the address it showed. If the connection now comes from
			// somewhere else (a CDN edge, a different proxy), trusting this one would be a guess.
			$shown = isset( $_POST['peer'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['peer'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce and capability checked in $this->guard() at the top of this handler.
			if ( IpUtils::is_public( $peer ) ) {
				$this->back( 'general', 'proxy_public', array(), true );
			}
			if ( $shown !== $peer ) {
				$this->back( 'general', 'peer_changed', array(), true );
			}
			$values['ip_source']       = $source;
			$values['trusted_proxies'] = array_merge( (array) $values['trusted_proxies'], array( $peer ) );
			$values                    = Settings::sanitize( $values );
			$message                   = $this->guard_new_ip_settings( $values );
			$this->save( $values );
			$this->back( 'general', 'proxy_trusted', array_merge( $message, array( 'ip' => $peer ) ) );
		}

		$this->back( 'general', 'unknown_action', array(), true );
	}

	/**
	 * Self-lockout guard for the IP setup fixes.
	 *
	 * Changing the IP source changes which address the admin appears to have, so
	 * the check runs against the NEW settings and the IP they would resolve to,
	 * not the current one. If the admin would be refused, a bannable address is
	 * added to the allowlist; a shared one (proxy, loopback) never is, and the
	 * change is refused instead.
	 *
	 * @param array<string, mixed> $values New, sanitised settings. The allowlist may be extended.
	 * @return array<string, string> Message arguments to add to the success redirect (empty if nothing was needed).
	 */
	private function guard_new_ip_settings( array &$values ): array {
		list( $request, $allowlistable ) = $this->request_under( $values );
		$reason                          = $this->would_block_current_admin( $values, $request );
		if ( null === $reason ) {
			return array();
		}
		if ( ! $allowlistable ) {
			$this->back( 'general', 'shared_refusal', array( 'detail' => $reason ), true );
		}
		$values['allowlist'][] = $request->ip();
		$values                = Settings::sanitize( $values );
		return array(
			'allow'  => $request->ip(),
			'detail' => $reason,
		);
	}

	/**
	 * The admin's own request as it would look under other settings.
	 *
	 * @param array<string, mixed> $values Settings.
	 * @return array{0: Request, 1: bool} The request, and whether its IP may be put on the allowlist
	 *                                    (the IP is the counter subject and is not shared, loopback or a proxy).
	 */
	private function request_under( array $values ): array {
		$server   = wp_unslash( $_SERVER );
		$resolver = new IpResolver( (string) $values['ip_source'], (array) $values['trusted_proxies'], Plugin::allows_private_client_ips() );
		$ip       = $resolver->resolve( $server );
		$subject  = $resolver->rejected_subject( $server );
		$single   = IpUtils::is_bannable( $ip, $resolver->proxies(), $resolver->suspends_bans( $server ) );
		$bannable = '' !== $subject || $single;
		// A forwarding header from a peer that is not a listed proxy may be an unlisted CDN edge: never allowlist it.
		$edge = false;
		foreach ( IpResolver::FORWARDING_HEADERS as $header ) {
			if ( isset( $server[ $header ] ) ) {
				$edge = ! IpUtils::matches_any( trim( (string) ( $server['REMOTE_ADDR'] ?? '' ) ), $resolver->proxies() );
				break;
			}
		}
		$request = Request::from_globals(
			$ip,
			$server,
			array(),
			array(),
			static function (): bool {
				return false;
			},
			static function (): bool {
				return false;
			},
			$resolver->is_local_request( $server ),
			$bannable,
			$subject
		);
		return array( $request, '' === $subject && $single && ! $edge );
	}

	/**
	 * Would the new settings refuse the admin who is saving them?
	 *
	 * Checks the rules that apply to every page (IP blocklist, country, User-Agent)
	 * against the admin's own request.
	 *
	 * @param array<string, mixed> $values  Proposed settings.
	 * @param Request|null         $request The request to test; the current one by default.
	 * @return string|null The block reason, or null if the admin would get in.
	 */
	private function would_block_current_admin( array $values, ?Request $request = null ): ?string {
		$request = $request ?? $this->plugin->current_request();
		$ip      = $request->ip();
		if ( '' === $ip || $request->is_local() || IpUtils::matches_any( $ip, IpUtils::without_broad( (array) $values['allowlist'] ) ) ) {
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
		$id     = isset( $_POST['rule'] ) ? sanitize_key( wp_unslash( $_POST['rule'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce and capability checked in $this->guard() at the top of this handler.
		$values = $this->plugin->settings()->to_array();
		if ( ! isset( $values['rules'][ $id ] ) ) {
			$this->back( 'dashboard', 'unknown_rule', array(), true );
		}
		// The uploads rule drives the network-wide uploads/.htaccess: network admins only on multisite.
		if ( 'uploads_php' === $id && ! current_user_can( self::FIREWALL_CAPABILITY ) ) {
			$this->back( 'dashboard', 'managed_by_network', array(), true );
		}
		$values['rules'][ $id ]['enabled'] = empty( $values['rules'][ $id ]['enabled'] );
		$message                           = array(
			'rule'  => $id,
			'state' => $values['rules'][ $id ]['enabled'] ? 'on' : 'off',
		);

		// Same self-lockout guard as the Rules tab save (RT-27).
		if ( $values['rules'][ $id ]['enabled'] && in_array( $id, array( 'ip_blocklist', 'country', 'user_agent' ), true ) ) {
			list( $request, $allowlistable ) = $this->request_under( $values );
			$self_block                      = $this->would_block_current_admin( $values, $request );
			if ( null !== $self_block ) {
				if ( ! $allowlistable ) {
					$this->back( 'dashboard', 'shared_refusal', array( 'detail' => $self_block ), true );
				}
				$values['allowlist'][] = $request->ip();
				$values                = Settings::sanitize( $values );
				$message['allow']      = $request->ip();
				$message['detail']     = $self_block;
			}
		}
		$this->save( Settings::sanitize( $values ) );
		$this->back( 'dashboard', 'rule_toggled', $message );
	}

	/**
	 * URL of the "Block IP" action for one address, with a nonce that is only valid for that address.
	 *
	 * @param string $ip   A single IP address.
	 * @param string $back Tab to return to: log or traffic.
	 * @return string URL, already HTML-escaped by wp_nonce_url() (& is &amp;); pass it through esc_url() for attributes.
	 */
	public static function block_ip_url( string $ip, string $back = 'log' ): string {
		$args = array(
			'action' => 'wp_bouncer_block_ip',
			'ip'     => rawurlencode( $ip ),
		);
		if ( 'traffic' === $back ) {
			$args['back'] = 'traffic';
		}
		return wp_nonce_url( add_query_arg( $args, admin_url( 'admin-post.php' ) ), 'wp_bouncer_block_ip|' . $ip );
	}

	/**
	 * Add one IP to the blocklist (from the log, traffic log or dashboard).
	 *
	 * GET link carrying a per-address nonce: a nonce made for one address is
	 * refused for any other. A single address, or the counter-subject network
	 * of an IPv6 address (the log shows one address per /64, see CounterSubject).
	 */
	public function handle_block_ip(): void {
		$ip = isset( $_GET['ip'] ) ? trim( sanitize_text_field( wp_unslash( $_GET['ip'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the nonce is bound to this value and checked by $this->guard() on the next line.
		$this->guard( 'wp_bouncer_block_ip|' . $ip );
		$back = isset( $_GET['back'] ) && 'traffic' === $_GET['back'] ? 'traffic' : 'log'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce and capability checked in $this->guard() above.
		if ( ! IpUtils::is_valid( $ip ) && ! self::is_subject_network( $ip ) ) {
			$this->back( $back, 'ip_invalid', array(), true );
		}
		if ( IpUtils::in_range( $this->plugin->client_ip(), $ip ) ) {
			$this->back( $back, 'ip_own', array(), true );
		}
		$values                                     = $this->plugin->settings()->to_array();
		$values['rules']['ip_blocklist']['ips'][]   = $ip;
		$values['rules']['ip_blocklist']['enabled'] = true;
		$this->save( Settings::sanitize( $values ) );
		$this->back( $back, 'ip_blocked', array( 'ip' => $ip ) );
	}

	/**
	 * Is the value exactly the counter-subject network of an IPv6 address (e.g. 2001:db8:1:2::/64)?
	 * Only those ranges can be blocked from the log, never an arbitrary range.
	 *
	 * @param string $value Candidate "network/prefix".
	 */
	public static function is_subject_network( string $value ): bool {
		if ( ! str_contains( $value, '/' ) || ! IpUtils::is_valid_range( $value ) ) {
			return false;
		}
		list( $network, $bits ) = explode( '/', $value, 2 );
		return IpUtils::is_ipv6( $network ) && CounterSubject::of( $network, (int) $bits ) === $value;
	}

	/** Lift login lockouts and every temporary ban for an IP. */
	public function handle_unlock_ip(): void {
		$this->guard( 'wp_bouncer_unlock_ip' );
		$ip = isset( $_POST['ip'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['ip'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce and capability checked in $this->guard() at the top of this handler.
		if ( ! IpUtils::is_valid( $ip ) ) {
			$this->back( 'tools', 'ip_unlock_invalid', array(), true );
		}
		$this->plugin->login_guard()->clear( $ip );
		// Subject keys (the whole IPv6 network) and the exact-string keys of bans placed before the upgrade.
		$counter_keys = array_merge( SensitiveFileRule::keys_for( $ip ), NotFoundFloodRule::keys_for( $ip ) );
		$store_keys   = array_merge(
			RateLimitRule::keys_for( $ip ),
			$counter_keys,
			Firewall::log_keys( $ip, array( RateLimitRule::ID, SensitiveFileRule::ID, NotFoundFloodRule::ID ) )
		);
		foreach ( $store_keys as $key ) {
			$this->plugin->store()->delete( $key );
		}
		$counter = $this->plugin->attempt_counter();
		foreach ( $counter_keys as $key ) {
			$counter->delete( $key );
		}
		$this->back( 'tools', 'ip_unlocked', array( 'ip' => $ip ) );
	}

	/** Send a test alert email. */
	public function handle_test_alert(): void {
		$this->guard( 'wp_bouncer_test_alert' );
		$result = $this->plugin->alerts()->send_test();
		if ( true !== $result ) {
			$this->back( 'general', 'test_failed', array( 'detail' => $result ), true );
		}
		$this->back( 'general', 'test_sent', array( 'detail' => implode( ', ', $this->plugin->alerts()->recipients() ) ) );
	}

	/** Check whether the server runs PHP from the uploads folder. */
	public function handle_uploads_probe(): void {
		$this->guard( 'wp_bouncer_uploads_probe', self::FIREWALL_CAPABILITY );
		$result = $this->plugin->uploads_guard()->probe();
		$this->back( 'rules', 'probe_result', array( 'result' => $result['result'] ), in_array( $result['result'], array( 'unprotected', 'broken' ), true ), 'rule-uploads_php' );
	}

	/** Write (or remove) the uploads/.htaccess block now. */
	public function handle_uploads_sync(): void {
		$this->guard( 'wp_bouncer_uploads_sync', self::FIREWALL_CAPABILITY );
		$guard = $this->plugin->uploads_guard();
		delete_option( UploadsGuard::STATE_OPTION );
		$guard->maybe_sync();
		$state = get_option( UploadsGuard::STATE_OPTION );
		if ( empty( $state['ok'] ) ) {
			$this->back( 'rules', 'uploads_sync_failed', array(), true, 'rule-uploads_php' );
		}
		$this->back( 'rules', 'uploads_synced', array( 'state' => $guard->wants_htaccess() ? 'written' : 'removed' ), false, 'rule-uploads_php' );
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
			case 'retrying':
				return __( 'The server answered an uploaded file with an error. WP Bouncer will look again in a few minutes before changing anything.', 'wp-bouncer' );
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
		/**
		 * Fires after the activity log was emptied.
		 */
		do_action( 'wp_bouncer_log_cleared' );
		// Clearing the log is how an intruder covers tracks: leave a fresh row and tell the owner.
		$this->write_audit_row( 'Activity log cleared by ' . $this->actor() );
		$this->plugin->alerts()->on_log_cleared();
		$this->back( 'log', 'log_cleared' );
	}

	/** Download the (filtered) log as CSV. */
	public function handle_export_log(): void {
		$this->guard( 'wp_bouncer_export_log' );
		$filters = self::log_filters_from_request();

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="wp-bouncer-log-' . gmdate( 'Ymd-His' ) . '.csv"' );

		$out = fopen( 'php://output', 'w' );
		self::csv_row( $out, array( 'time_utc', 'ip', 'country', 'rule', 'action', 'reason', 'method', 'uri', 'user_agent' ) );
		for ( $page = 1; $page <= 100; $page++ ) {
			$rows = $this->plugin->log()->query( $filters, 1000, $page );
			foreach ( $rows as $row ) {
				self::csv_row(
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
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- closes the php://output stream used for the CSV download, not a file on disk.
		exit;
	}

	/**
	 * Write one CSV line in RFC 4180 form (quotes doubled, no backslash escape).
	 * Passes every fputcsv() argument explicitly: PHP 8.4 deprecates relying on
	 * the default escape character.
	 *
	 * @param resource          $out    Output stream.
	 * @param array<int, mixed> $fields Cell values.
	 */
	private static function csv_row( $out, array $fields ): void {
		fputcsv( $out, $fields, ',', '"', '' );
	}

	/** Empty the traffic log. */
	public function handle_clear_traffic(): void {
		$this->guard( 'wp_bouncer_clear_traffic' );
		$this->plugin->traffic_log()->clear();
		$this->back( 'traffic', 'traffic_cleared' );
	}

	/** Download the (filtered) traffic log as CSV. */
	public function handle_export_traffic(): void {
		$this->guard( 'wp_bouncer_export_traffic' );
		$filters = self::traffic_filters_from_request();

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="wp-bouncer-traffic-' . gmdate( 'Ymd-His' ) . '.csv"' );

		$out = fopen( 'php://output', 'w' );
		self::csv_row( $out, array( 'time_utc', 'ip', 'client', 'method', 'url', 'status', 'referrer', 'user_agent', 'user_id' ) );
		for ( $page = 1; $page <= 500; $page++ ) {
			$rows = $this->plugin->traffic_log()->query( $filters, 1000, $page );
			foreach ( $rows as $row ) {
				self::csv_row(
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
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- closes the php://output stream used for the CSV download, not a file on disk.
		exit;
	}

	/**
	 * Traffic filters from the query string.
	 *
	 * @return array<string, string>
	 */
	public static function traffic_filters_from_request(): array {
		// phpcs:disable WordPress.Security.NonceVerification -- read-only filters, sanitised here and passed to prepared queries; change no state.
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
		// phpcs:enable WordPress.Security.NonceVerification
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
		foreach ( array(
			'client' => 'client',
			'status' => 'status',
			'ip'     => 'ip',
			'search' => 's',
		) as $key => $param ) {
			if ( ! empty( $filters[ $key ] ) ) {
				$args[ $param ] = rawurlencode( $filters[ $key ] );
			}
		}
		return $args;
	}

	/**
	 * Stop spreadsheet formula injection in exported cells.
	 *
	 * @param mixed $value Cell value.
	 * @see CsvSanitizer::cell()
	 */
	public static function csv_safe( $value ): string {
		return CsvSanitizer::cell( $value );
	}

	/**
	 * Log filters from the query string.
	 *
	 * @return array<string, string>
	 */
	public static function log_filters_from_request(): array {
		// phpcs:disable WordPress.Security.NonceVerification -- read-only filters, sanitised here and passed to prepared queries; change no state.
		// Request param => log column. "log_action" avoids clashing with admin-post's "action".
		$filters = array();
		foreach ( array(
			'rule'       => 'rule',
			'log_action' => 'action',
			'country'    => 'country',
		) as $param => $column ) {
			if ( ! empty( $_REQUEST[ $param ] ) ) {
				$filters[ $column ] = sanitize_key( wp_unslash( $_REQUEST[ $param ] ) );
			}
		}
		if ( isset( $filters['country'] ) ) {
			$filters['country'] = strtoupper( $filters['country'] );
		}
		if ( ! empty( $_REQUEST['log_ip'] ) ) {
			// Exact match, so only a well-formed address is accepted. "log_ip": the redirect after blocking an IP already carries "ip".
			$ip = sanitize_text_field( wp_unslash( $_REQUEST['log_ip'] ) );
			if ( IpUtils::is_valid( $ip ) ) {
				// The log stores canonical text, so "::FFFF:1.2.3.4" or an upper-case IPv6 must match it too.
				$filters['ip'] = IpUtils::canonical( $ip );
			}
		}
		if ( ! empty( $_REQUEST['s'] ) ) {
			$filters['search'] = sanitize_text_field( wp_unslash( $_REQUEST['s'] ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification
		return $filters;
	}

	/**
	 * Turn log filters back into query args (inverse of log_filters_from_request()).
	 *
	 * @param array<string, string> $filters Filters.
	 * @return array<string, string>
	 */
	public static function log_filters_to_args( array $filters ): array {
		$map  = array(
			'rule'    => 'rule',
			'action'  => 'log_action',
			'country' => 'country',
			'ip'      => 'log_ip',
			'search'  => 's',
		);
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
		if ( empty( $_POST ) && ! empty( $_SERVER['CONTENT_LENGTH'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification -- only tests whether a POST body exists (post_max_size overflow); no value is read or used.
			$this->back( 'tools', 'geo_upload_error', array( 'upload' => UPLOAD_ERR_INI_SIZE ), true );
		}
		$this->guard( 'wp_bouncer_geo_import' );

		$file   = isset( $_FILES['geo_file'] ) && is_array( $_FILES['geo_file'] ) ? $_FILES['geo_file'] : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Missing -- only error, name and tmp_name are read, name through sanitize_file_name() and tmp_name through is_uploaded_file(); nonce and capability checked in $this->guard() above.
		$upload = (int) ( $file['error'] ?? UPLOAD_ERR_NO_FILE );

		$path    = '';
		$cleanup = false;
		$source  = '';

		if ( UPLOAD_ERR_NO_FILE !== $upload ) {
			if ( UPLOAD_ERR_OK !== $upload ) {
				$this->back( 'tools', 'geo_upload_error', array( 'upload' => $upload ), true );
			}
			$name = sanitize_file_name( wp_unslash( (string) ( $file['name'] ?? 'upload.csv' ) ) );
			if ( ! preg_match( '/\.(csv|csv\.gz|gz)$/i', $name ) ) {
				$this->back( 'tools', 'geo_bad_type', array(), true );
			}
			if ( empty( $file['tmp_name'] ) || ! is_uploaded_file( $file['tmp_name'] ) ) {
				$this->back( 'tools', 'geo_no_arrive', array(), true );
			}
			$path   = (string) $file['tmp_name'];
			$source = $name;
		} elseif ( ! empty( $_POST['geo_url'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce and capability checked in $this->guard() at the top of this handler.
			// Making the server fetch a URL is server-wide: network admins only on multisite.
			if ( ! current_user_can( self::FIREWALL_CAPABILITY ) ) {
				wp_die( esc_html__( 'You do not have permission to do that.', 'wp-bouncer' ), 403 );
			}
			$url = esc_url_raw( wp_unslash( $_POST['geo_url'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce and capability checked in $this->guard() at the top of this handler.
			if ( ! wp_http_validate_url( $url ) ) {
				$this->back( 'tools', 'geo_bad_url', array(), true );
			}
			list( $hosts, $allow_http ) = $this->geo_url_rules();
			if ( ! GeoUrlPolicy::allowed( $url, $hosts, $allow_http ) ) {
				$this->back( 'tools', 'geo_download_failed', array( 'detail' => __( 'That host is not on the list of allowed download hosts.', 'wp-bouncer' ) ), true );
			}
			$tmp = $this->download_geo_file( $url );
			if ( is_wp_error( $tmp ) ) {
				// The detail can name internal addresses: keep it in the debug log, show a generic message.
				if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
					error_log( 'WP Bouncer geo download failed: ' . $tmp->get_error_message() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- only with WP_DEBUG_LOG on.
				}
				$this->back( 'tools', 'geo_download_failed', array( 'detail' => __( 'The file could not be downloaded.', 'wp-bouncer' ) ), true );
			}
			$path    = $tmp;
			$cleanup = true;
			$source  = $url;
		} else {
			$this->back( 'tools', 'geo_choose', array(), true );
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
			$this->back( 'tools', 'geo_error', array( 'detail' => $error ), true );
		}

		// The Tools screen sees the running import and carries on with it.
		wp_safe_redirect( self::url( 'tools' ) );
		exit;
	}

	/**
	 * The geo import URL policy: allowed hosts, and whether http is accepted.
	 *
	 * @return array{0: string[], 1: bool}
	 */
	private function geo_url_rules(): array {
		/**
		 * Filters the hosts the geo importer may download from (https only).
		 *
		 * @param string[] $hosts Allowed host names.
		 */
		$hosts = (array) apply_filters( 'wp_bouncer_geo_import_hosts', GeoUrlPolicy::DEFAULT_HOSTS );
		/**
		 * Filters whether http URLs are accepted too. Off by default; for local test servers only.
		 *
		 * @param bool $allow Default false.
		 */
		return array( array_map( 'strval', $hosts ), (bool) apply_filters( 'wp_bouncer_geo_import_allow_http', false ) );
	}

	/**
	 * Download a geo CSV to a temporary file, with a size cap.
	 *
	 * Streams to disk through the safe HTTP API. Redirects are followed by hand
	 * (at most 3), each checked against the host policy. A response that reached
	 * the cap is treated as truncated and refused. The temporary file is deleted
	 * on every failure.
	 *
	 * @param string $url Validated, allow-listed URL.
	 * @return string|\WP_Error Temporary file path, or the error.
	 */
	private function download_geo_file( string $url ) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$limit = 200 * MB_IN_BYTES;
		$tmp   = wp_tempnam( $url );
		if ( ! $tmp ) {
			return new \WP_Error( 'wpb_geo_tmp', __( 'Could not create a temporary file.', 'wp-bouncer' ) );
		}
		// Redirects are followed by hand so each hop is checked against the same host policy (RT-12).
		list( $hosts, $allow_http ) = $this->geo_url_rules();
		$current                    = $url;
		for ( $hop = 0; ; $hop++ ) {
			$response = wp_safe_remote_get(
				$current,
				array(
					'stream'              => true,
					'filename'            => $tmp,
					'limit_response_size' => $limit,
					'timeout'             => 120,
					'redirection'         => 0,
				)
			);
			if ( is_wp_error( $response ) ) {
				wp_delete_file( $tmp );
				return $response;
			}
			$status   = (int) wp_remote_retrieve_response_code( $response );
			$location = wp_remote_retrieve_header( $response, 'location' );
			if ( $status < 300 || $status > 399 || '' === $location ) {
				break;
			}
			// More than one Location header comes back as an array: refuse it rather than guess.
			$next = 3 > $hop && is_string( $location ) ? GeoUrlPolicy::redirect_target( $current, $location, $hosts, $allow_http ) : null;
			if ( null === $next || ! wp_http_validate_url( $next ) ) {
				wp_delete_file( $tmp );
				return new \WP_Error( 'wpb_geo_redirect', __( 'The download redirected somewhere that is not allowed.', 'wp-bouncer' ) );
			}
			$current = $next;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			wp_delete_file( $tmp );
			/* translators: %d: HTTP status code. */
			return new \WP_Error( 'wpb_geo_http', sprintf( __( 'The server answered with HTTP status %d.', 'wp-bouncer' ), $code ) );
		}
		clearstatcache( true, $tmp );
		// Reaching the limit exactly means the body was cut off, so >= and not >.
		if ( filesize( $tmp ) >= $limit ) {
			wp_delete_file( $tmp );
			return new \WP_Error( 'wpb_geo_too_big', __( 'The download is larger than the 200 MB limit.', 'wp-bouncer' ) );
		}
		return $tmp;
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
		wp_send_json_success( $progress );
	}

	/** Run one import step without JavaScript, then return to the Tools tab. */
	public function handle_geo_step(): void {
		$this->guard( 'wp_bouncer_geo_step' );
		try {
			$progress = $this->plugin->geo_import()->step( self::geo_step_seconds() );
		} catch ( \Throwable $e ) {
			$this->back( 'tools', 'geo_error', array( 'detail' => $e->getMessage() ), true );
		}
		if ( $progress['done'] ) {
			$this->back(
				'tools',
				'geo_done',
				array(
					'n'       => $progress['imported'],
					'skipped' => $progress['skipped'],
				)
			);
		}
		wp_safe_redirect( self::url( 'tools' ) );
		exit;
	}

	/** Stop a running import, keeping what has loaded. */
	public function handle_geo_cancel(): void {
		$this->guard( 'wp_bouncer_geo_cancel' );
		$this->plugin->geo_import()->cancel();
		$this->back( 'tools', 'geo_cancelled', array(), true );
	}

	/*
	 * ------------------------------------------------------------------
	 * View helpers
	 * ----------------------------------------------------------------
	 */

	/**
	 * Output an on/off switch for a rule's "enabled" flag.
	 *
	 * @param string $id       Rule id.
	 * @param bool   $checked  Current state.
	 * @param bool   $disabled Show the switch but don't let this user change it.
	 * @param string $title    Rule title: the switch's accessible name, so a screen reader says "IP blocklist, switch, on".
	 */
	public static function rule_switch( string $id, bool $checked, bool $disabled = false, string $title = '' ): void {
		printf(
			'<label class="wpb-switch"><input type="checkbox" role="switch" name="wp_bouncer[rules][%1$s][enabled]" value="1" %2$s %4$s><span class="wpb-slider" aria-hidden="true"></span><span class="screen-reader-text">%3$s</span></label>',
			esc_attr( $id ),
			checked( $checked, true, false ),
			'' !== $title ? esc_html( $title ) : esc_html__( 'Enabled', 'wp-bouncer' ),
			disabled( $disabled, true, false )
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
			case BlockLogInterface::ACTION_SUPPRESSED:
				return __( 'Suppressed', 'wp-bouncer' );
			default:
				return __( 'Blocked', 'wp-bouncer' );
		}
	}
}
