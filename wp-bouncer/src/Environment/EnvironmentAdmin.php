<?php
/**
 * Where the environment checks show up: Dashboard tab, Site Health, one notice.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Environment;

use WPBouncer\Admin\FirewallCapability;
use WPBouncer\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Nothing here runs at load time or on the firewall path: a report is built
 * lazily, once per request, when a screen asks for it. Visibility is
 * wpb_manage_firewall (network admins on multisite), checked on the server.
 * Nothing is persisted except the notice's dismissal (user meta with a state
 * id and the server's time). No requests are made.
 */
final class EnvironmentAdmin {

	public const DISMISS_ACTION = 'wp_bouncer_env_dismiss';
	public const DISMISS_META   = 'wpb_env_notice_dismissed';
	public const DISMISS_DAYS   = 30;

	/**
	 * The instance the plugin registered (so a screen reuses its report).
	 *
	 * @var EnvironmentAdmin|null
	 */
	private static ?EnvironmentAdmin $shared = null;
	/**
	 * Time source.
	 *
	 * @var Clock
	 */
	private Clock $clock;
	/**
	 * Support policy.
	 *
	 * @var SupportPolicy
	 */
	private SupportPolicy $policy;
	/**
	 * Environment.
	 *
	 * @var EnvironmentInterface
	 */
	private EnvironmentInterface $env;
	/**
	 * This request's report.
	 *
	 * @var Report|null
	 */
	private ?Report $report = null;
	/**
	 * The filtered checks (built-ins kept, extras).
	 *
	 * @var array{0: CheckInterface[], 1: CheckInterface[]}|null
	 */
	private ?array $checks = null;

	/**
	 * Set up the EnvironmentAdmin.
	 *
	 * @param Clock|null                $clock  Time source.
	 * @param EnvironmentInterface|null $env    Environment (the real server by default).
	 * @param SupportPolicy|null        $policy Support policy.
	 */
	public function __construct( ?Clock $clock = null, ?EnvironmentInterface $env = null, ?SupportPolicy $policy = null ) {
		$this->clock  = $clock ?? new Clock();
		$this->env    = $env ?? new RuntimeEnvironment();
		$this->policy = $policy ?? new SupportPolicy();
	}

	/** The registered instance, or a new one when none is (a screen rendered outside a normal boot). */
	public static function shared(): self {
		return self::$shared ?? new self();
	}

	/** Hook in (admin and cron requests only; see Plugin::register()). */
	public function register(): void {
		self::$shared = $this;
		( new SiteHealth( array( $this, 'report' ), array( $this, 'can_view' ) ) )->register();
		add_action( is_multisite() ? 'network_admin_notices' : 'admin_notices', array( $this, 'notice' ) );
		add_action( 'admin_post_' . self::DISMISS_ACTION, array( $this, 'handle_dismiss' ) );
	}

	/** May this user see the results? Checked on the server wherever they are shown. */
	public function can_view(): bool {
		return current_user_can( FirewallCapability::NAME );
	}

	/**
	 * A filter may return anything: treat its result as untyped.
	 *
	 * @param mixed $value Value.
	 */
	private static function anything( mixed $value ): mixed {
		return $value;
	}

	/**
	 * The checks to run after the filter: built-ins a host did not remove, and valid extras.
	 *
	 * @return array{0: CheckInterface[], 1: CheckInterface[]} Built-ins to keep, third-party checks.
	 */
	private function checks(): array {
		if ( null === $this->checks ) {
			$builtins = EnvironmentReport::builtins( $this->clock, $this->policy );
			/**
			 * Filters the environment checks. Built-ins come first; invalid or duplicate ids are dropped.
			 *
			 * @param CheckInterface[] $checks Checks.
			 */
			$filtered = self::anything( apply_filters( 'wp_bouncer_environment_checks', $builtins ) );
			$list     = is_array( $filtered ) ? $filtered : $builtins;
			// A built-in a host removed with the filter stays removed.
			$this->checks = array(
				array_values( array_filter( $builtins, static fn( $c ): bool => in_array( $c, $list, true ) ) ),
				array_values( array_filter( $list, static fn( $c ): bool => $c instanceof CheckInterface && ! in_array( $c, $builtins, true ) ) ),
			);
		}
		return $this->checks;
	}

	/** This request's report (built on first use). */
	public function report(): Report {
		if ( null === $this->report ) {
			list( $keep, $extra ) = $this->checks();
			$this->report         = ( new EnvironmentReport( $keep ) )->run( $this->env, $extra );
		}
		return $this->report;
	}

	/** Print the Dashboard tab section. */
	public function render_dashboard_section(): void {
		if ( ! $this->can_view() ) {
			return;
		}
		$report = $this->report();
		require dirname( __DIR__ ) . '/Admin/views/partials/environment.php';
	}

	/**
	 * The past-end-of-life findings, from the two version checks only (no full report, no SQL).
	 *
	 * @return array<string, string> Short sentence by check key (php, db), and 'state' as a string id.
	 */
	public function eol_findings(): array {
		$out    = array();
		$state  = array();
		$wanted = array(
			'wpb_php_version' => 'php',
			'wpb_db_version'  => 'db',
		);
		// Only the two version checks, and only if a host has not removed them with the filter.
		foreach ( $this->checks()[0] as $check ) {
			if ( ! isset( $wanted[ $check->id() ] ) ) {
				continue;
			}
			$result = $check->run( $this->env );
			if ( Severity::Critical === $result->severity ) {
				$out[ $wanted[ $check->id() ] ] = $result->value;
				$state[]                        = strtolower( str_replace( ' ', ':', $result->value ) );
			}
		}
		if ( $out ) {
			$out['state'] = implode( '|', $state );
		}
		return $out;
	}

	/**
	 * Has this user dismissed the current notice recently?
	 *
	 * @param string $state Id of the end-of-life state being shown.
	 */
	private function dismissed( string $state ): bool {
		$meta = get_user_meta( get_current_user_id(), self::DISMISS_META, true );
		return is_array( $meta )
			&& ( $meta['state'] ?? '' ) === $state
			&& $this->within_dismissal( (int) ( $meta['at'] ?? 0 ) );
	}

	/**
	 * Is a dismissal time still current? One in the future (a clock that moved back) is not.
	 *
	 * @param int $at When it was dismissed.
	 */
	private function within_dismissal( int $at ): bool {
		$age = $this->clock->now() - $at;
		return $age >= 0 && $age < self::DISMISS_DAYS * 86400;
	}

	/** Show the site-wide notice: only for PHP or a database past its end of life. */
	public function notice(): void {
		if ( ! $this->can_view() ) {
			return;
		}
		// The plugin's own Dashboard tab already says it in full.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only: decides whether to show a notice.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only: decides whether to show a notice.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'dashboard';
		if ( 'wp-bouncer' === $page && 'dashboard' === $tab ) {
			return;
		}
		$found = $this->eol_findings();
		if ( ! $found || $this->dismissed( $found['state'] ) ) {
			return;
		}
		unset( $found['state'] );
		$dismiss = wp_nonce_url( admin_url( 'admin-post.php?action=' . self::DISMISS_ACTION ), self::DISMISS_ACTION );
		printf(
			'<div class="notice notice-warning" role="alert"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a> | <a href="%5$s">%6$s</a></p></div>',
			esc_html__( 'WP Bouncer:', 'wp-bouncer' ),
			/* translators: %s: versions such as "PHP 8.2". */
			esc_html( sprintf( __( '%s no longer receives security fixes (by WP Bouncer\'s bundled support policy; some hosts backport fixes).', 'wp-bouncer' ), implode( ', ', $found ) ) ),
			esc_url( admin_url( 'site-health.php' ) ),
			esc_html__( 'Site Health', 'wp-bouncer' ),
			esc_url( $dismiss ),
			esc_html__( 'Dismiss for 30 days', 'wp-bouncer' )
		);
	}

	/** Dismiss the notice for the current user. */
	public function handle_dismiss(): void {
		if ( ! $this->can_view() ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'wp-bouncer' ), 403 );
		}
		check_admin_referer( self::DISMISS_ACTION );
		$found = $this->eol_findings();
		// Only server-side values are stored: the state and the server's time.
		update_user_meta(
			get_current_user_id(),
			self::DISMISS_META,
			array(
				'at'    => $this->clock->now(),
				'state' => $found['state'] ?? '',
			)
		);
		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url() );
		exit;
	}
}
