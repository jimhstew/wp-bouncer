<?php
/**
 * Keeps PHP from running in wp-content/uploads.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Hardening;

use WPBouncer\Admin\FirewallCapability;
use WPBouncer\Firewall\Firewall;
use WPBouncer\Firewall\Request;
use WPBouncer\Installer;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Rule id "uploads_php". Settings:
 * - enabled (bool)
 * - htaccess (bool): keep a "# BEGIN WP Bouncer" block in uploads/.htaccess.
 * - check_uploads (bool): refuse uploads that are scripts in disguise.
 *
 * The .htaccess block is written or removed when the setting changes (checked
 * cheaply on each request against a stored fingerprint), and removed when the
 * plugin is deactivated or deleted. Anything else in that .htaccess is left alone.
 *
 * nginx ignores .htaccess. The Rules tab shows the equivalent nginx rule, and
 * "Test now" checks what the server actually does.
 *
 * Safety net: some Apache hosts don't allow access rules in .htaccess
 * (AllowOverride), and then every file in uploads, images included, gets a
 * 500 error while the block is there. After writing the block, a one-off cron
 * job (and every "Test now") fetches a harmless text file from uploads. If
 * the server answers with a 5xx error, the block is removed again, marked
 * "broken" so it isn't rewritten, and the admin screens say so.
 */
final class UploadsGuard {

	public const ID = 'uploads_php';

	/** What was last written, so the file is only touched when something changes. */
	public const STATE_OPTION = 'wp_bouncer_uploads_htaccess';

	/** Result of the last "Test now". */
	public const PROBE_OPTION = 'wp_bouncer_uploads_probe';

	/** One-off cron hook that checks uploads still load after the block is written. */
	public const CHECK_HOOK = 'wp_bouncer_uploads_check';

	/** Least seconds between the two failures that remove the block. */
	public const RECHECK_SECONDS = 300;

	/** A failure older than this starts a new count. */
	public const STREAK_SECONDS = 3600;

	/**
	 * Plugin instance.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Set up the UploadsGuard.
	 *
	 * @param Plugin $plugin Plugin.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/** Hook into WordPress. */
	public function register(): void {
		add_action( 'init', array( $this, 'maybe_sync' ) );
		add_action( self::CHECK_HOOK, array( $this, 'cron_check' ) );
		add_action( Installer::CRON_HOOK, array( $this, 'cron_sweep' ) );
		if ( ! Plugin::is_disabled() ) {
			add_filter( 'wp_handle_upload_prefilter', array( $this, 'filter_upload' ) );
			add_filter( 'wp_handle_sideload_prefilter', array( $this, 'filter_upload' ) );
		}
	}

	/**
	 * Get this component's settings.
	 *
	 * @return array<string, mixed> This rule's settings.
	 */
	private function settings(): array {
		return $this->plugin->settings()->rule( self::ID );
	}

	/** Should the .htaccess block be present? Not while WP_BOUNCER_DISABLE is on. */
	public function wants_htaccess(): bool {
		if ( Plugin::is_disabled() ) {
			return false;
		}
		$s = $this->settings();
		return ! empty( $s['enabled'] ) && ! empty( $s['htaccess'] );
	}

	/** Full path of uploads/.htaccess, or '' if uploads isn't available. */
	public static function htaccess_path(): string {
		$uploads = wp_upload_dir( null, false );
		return empty( $uploads['error'] ) && ! empty( $uploads['basedir'] ) ? $uploads['basedir'] . '/.htaccess' : '';
	}

	/** Fingerprint of what the .htaccess block should be. */
	private function wanted_state(): string {
		return $this->wants_htaccess() ? 'on:' . md5( implode( "\n", UploadsPolicy::htaccess_lines() ) ) : 'off';
	}

	/**
	 * Write or remove the block if the setting changed since last time.
	 * After a failed write, tries again at most once an hour.
	 */
	public function maybe_sync(): void {
		$want  = $this->wanted_state();
		$state = get_option( self::STATE_OPTION );
		if ( is_array( $state ) && ( $state['want'] ?? '' ) === $want && ( ! empty( $state['ok'] ) || ! empty( $state['broken'] ) || time() - (int) ( $state['time'] ?? 0 ) < HOUR_IN_SECONDS ) ) {
			return;
		}
		$ok = $this->sync();
		self::save_state( $want, $ok, false );
		if ( $ok && $this->wants_htaccess() && ! wp_next_scheduled( self::CHECK_HOOK ) ) {
			wp_schedule_single_event( time(), self::CHECK_HOOK );
		}
	}

	/**
	 * Save state.
	 *
	 * @param string $want   Fingerprint.
	 * @param bool   $ok     The file matches it.
	 * @param bool   $broken The block was removed because uploads stopped loading.
	 */
	private static function save_state( string $want, bool $ok, bool $broken ): void {
		update_option(
			self::STATE_OPTION,
			array(
				'want'   => $want,
				'ok'     => $ok,
				'broken' => $broken,
				'time'   => time(),
			),
			true
		);
	}

	/** Was the block removed because the server failed with it in place? */
	public static function is_broken(): bool {
		$state = get_option( self::STATE_OPTION );
		return is_array( $state ) && ! empty( $state['broken'] );
	}

	/**
	 * Count consecutive serving failures. The block comes out only after two
	 * failures at least RECHECK_SECONDS apart; a success resets the count.
	 *
	 * @param array<string, mixed> $state  Stored state (keys fail_streak, fail_time).
	 * @param string               $result 'ok', 'broken' or 'unknown'.
	 * @param int                  $now    Current time.
	 * @return array{fail_streak: int, fail_time: int, remove: bool}
	 */
	public static function serving_streak( array $state, string $result, int $now ): array {
		$streak = (int) ( $state['fail_streak'] ?? 0 );
		$time   = (int) ( $state['fail_time'] ?? 0 );
		if ( $streak >= 1 && $now - $time > self::STREAK_SECONDS ) {
			// A failure from long ago is not "consecutive" with a new one.
			$streak = 0;
			$time   = 0;
		}
		if ( 'ok' === $result ) {
			return array(
				'fail_streak' => 0,
				'fail_time'   => 0,
				'remove'      => false,
			);
		}
		if ( 'broken' !== $result || ( $streak >= 1 && $now - $time < self::RECHECK_SECONDS ) ) {
			// Unknown results, and failures too soon after the last one, change nothing.
			return array(
				'fail_streak' => $streak,
				'fail_time'   => $time,
				'remove'      => false,
			);
		}
		++$streak;
		return array(
			'fail_streak' => $streak,
			'fail_time'   => $now,
			'remove'      => $streak >= 2,
		);
	}

	/** Daily cron callback: sweep leftovers. */
	public function cron_sweep(): void {
		self::sweep_stale_files();
	}

	/**
	 * Delete test and check files that a request left behind in uploads (older than an hour).
	 *
	 * @return int Number of files deleted.
	 */
	public static function sweep_stale_files(): int {
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			return 0;
		}
		$deleted = 0;
		foreach ( (array) scandir( $uploads['basedir'] ) as $name ) {
			if ( ! fnmatch( 'wp-bouncer-test-*.php', $name ) && ! fnmatch( 'wp-bouncer-check-*.txt', $name ) ) {
				continue;
			}
			$file = $uploads['basedir'] . '/' . $name;
			if ( is_file( $file ) && filemtime( $file ) < time() - HOUR_IN_SECONDS ) {
				wp_delete_file( $file );
				++$deleted;
			}
		}
		return $deleted;
	}

	/** Cron callback for CHECK_HOOK. */
	public function cron_check(): void {
		if ( self::is_broken() && $this->wants_htaccess() && ! self::block_present() ) {
			$this->retry_broken();
			return;
		}
		$this->run_serving_check();
	}

	/**
	 * A day after the block was taken out for breaking uploads, put it back and
	 * look again. If uploaded files load, it stays; otherwise it comes out again
	 * and the next try is a day later.
	 */
	private function retry_broken(): void {
		self::write_block();
		if ( 'ok' === $this->check_serving() ) {
			self::save_state( $this->wanted_state(), true, false );
			$this->log_alert( 'Restored the uploads/.htaccess block: uploaded files load again with it in place' );
			return;
		}
		self::remove_block();
		wp_schedule_single_event( time() + DAY_IN_SECONDS, self::CHECK_HOOK );
	}

	/**
	 * Write an alert-level row to the activity log.
	 *
	 * @param string $reason What happened.
	 */
	private function log_alert( string $reason ): void {
		$this->plugin->log_writer()->record(
			array(
				'ip'     => '',
				'rule'   => self::ID,
				'action' => BlockLogInterface::ACTION_ALERT,
				'reason' => $reason,
				'method' => $this->plugin->current_request()->method(),
			)
		);
	}

	/** Look again soon (once). */
	private function schedule_recheck(): void {
		if ( ! wp_next_scheduled( self::CHECK_HOOK ) ) {
			wp_schedule_single_event( time() + self::RECHECK_SECONDS + 30, self::CHECK_HOOK );
		}
	}

	/**
	 * With the block in place, do uploaded files still load? If not twice in a
	 * row (5 minutes apart), take the block out again.
	 *
	 * @return string 'ok', 'broken' (block removed), 'retry' (first error seen, checking again soon) or 'unknown'.
	 */
	public function run_serving_check(): string {
		if ( ! self::block_present() ) {
			return 'unknown';
		}
		$result = $this->check_serving();
		$state  = get_option( self::STATE_OPTION );
		$state  = is_array( $state ) ? $state : array();
		$next   = self::serving_streak( $state, $result, time() );

		if ( 'broken' === $result && $next['remove'] ) {
			self::remove_block();
			self::save_state( $this->wanted_state(), false, true );
			$this->log_alert( 'Removed the uploads/.htaccess block: with it in place the server answered uploaded files with an error' );
			// Try again tomorrow: the error may have been the host's, not the block's.
			wp_schedule_single_event( time() + DAY_IN_SECONDS, self::CHECK_HOOK );
			return 'broken';
		}

		if ( (int) ( $state['fail_streak'] ?? 0 ) !== $next['fail_streak'] || (int) ( $state['fail_time'] ?? 0 ) !== $next['fail_time'] ) {
			update_option(
				self::STATE_OPTION,
				array_merge(
					$state,
					array(
						'fail_streak' => $next['fail_streak'],
						'fail_time'   => $next['fail_time'],
					)
				),
				true
			);
		}
		if ( 'broken' === $result ) {
			$this->schedule_recheck();
			return 'retry';
		}
		if ( 'unknown' === $result && $next['fail_streak'] > 0 ) {
			// An open streak must not hang on one inconclusive answer.
			$this->schedule_recheck();
		}
		return $result;
	}

	/**
	 * Fetch a harmless text file from uploads.
	 *
	 * @return string 'ok' (it loaded), 'broken' (5xx error) or 'unknown' (the site can't reach itself, or something else).
	 */
	public function check_serving(): string {
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) ) {
			return 'unknown';
		}
		$name = 'wp-bouncer-check-' . wp_generate_password( 12, false ) . '.txt';
		$path = $uploads['basedir'] . '/' . $name;
		if ( false === file_put_contents( $path, 'wpb-ok' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions -- local file in uploads or the site root; WP_Filesystem needs credentials and is not loaded in cron, and failure is reported by the caller.
			return 'unknown';
		}
		$response = wp_remote_get( $uploads['baseurl'] . '/' . $name, self::loopback_args() );
		wp_delete_file( $path );
		if ( is_wp_error( $response ) ) {
			return 'unknown';
		}
		return UploadsPolicy::interpret_serving( (int) wp_remote_retrieve_response_code( $response ), (string) wp_remote_retrieve_body( $response ), 'wpb-ok' );
	}

	/**
	 * Build arguments for loopback requests.
	 *
	 * @return array<string, mixed> Arguments for requests the site makes to itself.
	 */
	private static function loopback_args(): array {
		return array(
			'timeout'     => 10,
			'redirection' => 0,
			/** This filter is documented in wp-includes/class-wp-http-streams.php */
			'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
		);
	}

	/**
	 * Make uploads/.htaccess match the setting.
	 *
	 * @return bool True when the file now matches.
	 */
	public function sync(): bool {
		return $this->wants_htaccess() ? self::write_block() : self::remove_block();
	}

	/** Write the block (creating the file if needed). */
	public static function write_block(): bool {
		$file = self::htaccess_path();
		if ( '' === $file ) {
			return false;
		}
		self::load_misc();
		return (bool) insert_with_markers( $file, UploadsPolicy::MARKER, UploadsPolicy::htaccess_lines() );
	}

	/** Remove the block, leaving the rest of the file as it was. */
	public static function remove_block(): bool {
		$file = self::htaccess_path();
		if ( '' === $file || ! file_exists( $file ) ) {
			return true;
		}
		$contents = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- local file in uploads or the site root; WP_Filesystem needs credentials and is not loaded in cron, and failure is reported by the caller.
		if ( false === strpos( $contents, '# BEGIN ' . UploadsPolicy::MARKER ) ) {
			return true;
		}
		$pattern = '/\n?# BEGIN ' . preg_quote( UploadsPolicy::MARKER, '/' ) . '\n.*?# END ' . preg_quote( UploadsPolicy::MARKER, '/' ) . '\n?/s';
		$cleaned = (string) preg_replace( $pattern, "\n", $contents );
		if ( '' === trim( $cleaned ) ) {
			// Only our block was in it, so the file was ours.
			return wp_delete_file_from_directory( $file, dirname( $file ) );
		}
		return false !== file_put_contents( $file, ltrim( $cleaned, "\n" ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- local file in uploads or the site root; WP_Filesystem needs credentials and is not loaded in cron, and failure is reported by the caller.
	}

	/** Is the block currently in uploads/.htaccess? */
	public static function block_present(): bool {
		$file = self::htaccess_path();
		return '' !== $file && file_exists( $file ) && false !== strpos( (string) file_get_contents( $file ), '# BEGIN ' . UploadsPolicy::MARKER ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- local file in uploads or the site root; WP_Filesystem needs credentials and is not loaded in cron, and failure is reported by the caller.
	}

	/**
	 * May the block be taken out of uploads/.htaccess by this request?
	 *
	 * On the main site of a network that file covers every site's uploads, so
	 * only someone who may manage the firewall (a network admin) can remove it.
	 * WP-CLI counts as trusted (shell access). Elsewhere anyone may.
	 */
	public static function may_remove_block(): bool {
		if ( ! is_multisite() || ! is_main_site() ) {
			return true;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}
		return current_user_can( FirewallCapability::NAME );
	}

	/**
	 * Called on deactivation and uninstall.
	 *
	 * @param bool $force Remove the block whoever is asking (uninstall: the plugin's files are going, so its block must too).
	 */
	public static function teardown( bool $force = false ): void {
		wp_clear_scheduled_hook( self::CHECK_HOOK );
		if ( $force || self::may_remove_block() ) {
			self::remove_block();
		}
		delete_option( self::STATE_OPTION );
		delete_option( self::PROBE_OPTION );
	}

	/** Load the admin include that defines insert_with_markers(). */
	private static function load_misc(): void {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
	}

	/**
	 * Refuse uploads that are scripts in disguise.
	 *
	 * @param array<string, mixed> $file Upload, as in $_FILES.
	 * @return array<string, mixed>
	 */
	public function filter_upload( $file ) {
		$s = $this->settings();
		if ( empty( $s['enabled'] ) || empty( $s['check_uploads'] ) || ! is_array( $file ) || ! empty( $file['error'] ) ) {
			return $file;
		}
		$name   = (string) ( $file['name'] ?? '' );
		$reason = UploadsPolicy::dangerous_name( $name );
		if ( null === $reason && ! empty( $file['tmp_name'] ) && UploadsPolicy::contains_php( (string) $file['tmp_name'], 52428800, $name ) ) {
			$reason = 'contains PHP code';
		}
		if ( null === $reason ) {
			return $file;
		}

		$request = $this->plugin->current_request();
		// One log row per IP per minute, checked against the budget before the de-dup key is set.
		$seen = Firewall::dedupe_key( self::ID, $request->ip() );
		if ( null === $this->plugin->store()->get( $seen ) && $this->plugin->write_budget()->peek( self::ID, true ) ) {
			$this->plugin->store()->set( $seen, 1, Firewall::LOG_DEDUPE_SECONDS );
			$this->log_refused_upload( $request, $name, $reason );
		}
		$file['error'] = sprintf(
			/* translators: %s: reason, such as "script extension .php". */
			__( 'WP Bouncer refused this file because it could run as code on the server (%s).', 'wp-bouncer' ),
			$reason
		);
		return $file;
	}

	/**
	 * Write the log row for a refused upload.
	 *
	 * @param Request $request Current request.
	 * @param string  $name    Uploaded file name.
	 * @param string  $reason  Why it was refused.
	 */
	private function log_refused_upload( Request $request, string $name, string $reason ): void {
		$this->plugin->log_writer()->record(
			array(
				'ip'         => $request->ip(),
				'country'    => (string) $this->plugin->geo()->lookup( $request->ip() ),
				'rule'       => self::ID,
				'action'     => BlockLogInterface::ACTION_BLOCKED,
				'reason'     => 'Upload refused: ' . sanitize_file_name( $name ) . ' (' . $reason . ')',
				'method'     => $request->method(),
				'uri'        => $request->uri(),
				'user_agent' => $request->user_agent(),
			)
		);
	}

	/**
	 * Find out whether the server runs PHP from uploads: place a tiny script
	 * there, request it, delete it.
	 *
	 * @return array{result: string, detail: string, time: int}
	 */
	public function probe(): array {
		$uploads = wp_upload_dir( null, false );
		$result  = array(
			'result' => 'unknown',
			'detail' => '',
			'time'   => time(),
		);
		if ( ! empty( $uploads['error'] ) ) {
			$result['detail'] = (string) $uploads['error'];
			return $this->save_probe( $result );
		}
		$serving = $this->run_serving_check();
		if ( 'broken' === $serving ) {
			$result['result'] = 'broken';
			$result['detail'] = __( 'block removed', 'wp-bouncer' );
			return $this->save_probe( $result );
		}
		if ( 'retry' === $serving ) {
			$result['result'] = 'retrying';
			$result['detail'] = __( 'first error seen; checking again in a few minutes', 'wp-bouncer' );
			return $this->save_probe( $result );
		}

		$name   = 'wp-bouncer-test-' . wp_generate_password( 12, false ) . '.php';
		$path   = $uploads['basedir'] . '/' . $name;
		$marker = 'wpb-php-ran';
		// The marker is split so it only appears in the output if PHP runs the file.
		$script = "<?php echo 'wpb-php-' . 'ran';\n";
		if ( false === file_put_contents( $path, $script ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions -- local file in uploads or the site root; WP_Filesystem needs credentials and is not loaded in cron, and failure is reported by the caller.
			$result['detail'] = __( 'Could not write a test file to the uploads folder.', 'wp-bouncer' );
			return $this->save_probe( $result );
		}

		$response = wp_remote_get( $uploads['baseurl'] . '/' . $name, self::loopback_args() );
		wp_delete_file( $path );

		if ( is_wp_error( $response ) ) {
			$result['detail'] = $response->get_error_message();
			return $this->save_probe( $result );
		}
		$status           = (int) wp_remote_retrieve_response_code( $response );
		$result['result'] = UploadsPolicy::interpret_probe( $status, (string) wp_remote_retrieve_body( $response ), $marker );
		$result['detail'] = 'HTTP ' . $status;
		return $this->save_probe( $result );
	}

	/**
	 * Save probe.
	 *
	 * @param array{result: string, detail: string, time: int} $result Probe result.
	 * @return array{result: string, detail: string, time: int}
	 */
	private function save_probe( array $result ): array {
		update_option( self::PROBE_OPTION, $result, false );
		return $result;
	}
}
