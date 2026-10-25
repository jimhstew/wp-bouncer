<?php
/**
 * Helpers shared by every integration test case.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration;

use WPBouncer\Geo\GeoImport;
use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Installer;
use WPBouncer\Storage\RedactionMigration;
use WPBouncer\Plugin;
use WPBouncer\Settings;
use WPBouncer\Traffic\TrafficRecorder;

/**
 * Mixed into IntegrationTestCase and AjaxTestCase.
 *
 * Plugin::boot() runs once per process (muplugins_loaded), so the singleton
 * and the hooks it registered are shared by all tests. These helpers give each
 * test a clean request, settings, mailbox and uploads folder.
 */
trait PluginHelpers {

	/** @var Plugin */
	protected $plugin;

	/** @var string */
	protected $uploads_dir = '';

	/** @var array<string, mixed> */
	private $server_backup = array();

	/** @var bool */
	private $ddl_test = false;

	/** Call from set_up() after the parent. */
	protected function wpb_set_up(): void {
		global $wpdb;
		$plugin = Plugin::instance();
		if ( null === $plugin ) {
			$this->fail( 'The plugin did not boot: is it loaded on muplugins_loaded?' );
		}
		$this->plugin        = $plugin;
		$this->server_backup = $_SERVER;

		foreach ( array( 'bouncer_log', 'bouncer_geo', 'bouncer_traffic', 'bouncer_counters' ) as $table ) {
			$wpdb->query( "DELETE FROM {$wpdb->prefix}{$table}" ); // phpcs:ignore WordPress.DB
		}

		reset_phpmailer_instance();

		$this->uploads_dir = sys_get_temp_dir() . '/wpb-uploads-' . uniqid( '', true );
		wp_mkdir_p( $this->uploads_dir );
		add_filter( 'upload_dir', array( $this, 'wpb_upload_dir' ) );

		// No test may reach the network (core's update checks fire on upgrader_process_complete and
		// would call api.wordpress.org). Runs last, so a test's own fake at the default priority wins.
		add_filter( 'pre_http_request', array( $this, 'wpb_block_http' ), PHP_INT_MAX, 3 );

		$this->reset_request();
		$plugin->reload_settings();
	}

	/**
	 * Refuse outbound HTTP that no test faked. It answers 503 rather than a WP_Error, because core's
	 * update checks turn a transport error into a (test-failing) _doing_it_wrong notice.
	 *
	 * @param false|array<string, mixed>|\WP_Error $pre  Earlier filters' answer.
	 * @param array<string, mixed>                  $args Request args.
	 * @param string                                $url  Request URL.
	 * @return false|array<string, mixed>|\WP_Error
	 */
	public function wpb_block_http( $pre, $args, $url ) {
		unset( $args );
		if ( false !== $pre ) {
			return $pre;
		}
		unset( $url );
		return array(
			'headers'  => array(),
			'body'     => '',
			'response' => array(
				'code'    => 503,
				'message' => 'Outbound HTTP is blocked in tests',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}

	/** Call from tear_down() before the parent. */
	protected function wpb_tear_down(): void {
		remove_filter( 'upload_dir', array( $this, 'wpb_upload_dir' ) );
		self::remove_tree( $this->uploads_dir );
		$_SERVER  = $this->server_backup;
		$_GET     = array();
		$_POST    = array();
		$_REQUEST = array();
		$_FILES   = array();
		if ( $this->ddl_test ) {
			$this->restore_schema();
		}
	}

	/**
	 * Point wp_upload_dir() at a throwaway folder.
	 *
	 * @param array<string, mixed> $dirs Upload dirs.
	 * @return array<string, mixed>
	 */
	public function wpb_upload_dir( $dirs ) {
		$dirs['basedir'] = $this->uploads_dir;
		$dirs['baseurl'] = 'http://example.org/wp-content/uploads';
		$dirs['path']    = $this->uploads_dir;
		$dirs['url']     = $dirs['baseurl'];
		$dirs['subdir']  = '';
		$dirs['error']   = false;
		return $dirs;
	}

	/**
	 * Remove a directory and everything in it.
	 *
	 * @param string $dir Directory.
	 */
	protected static function remove_tree( string $dir ): void {
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return;
		}
		foreach ( (array) scandir( $dir ) as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			$path = $dir . '/' . $name;
			if ( is_dir( $path ) && ! is_link( $path ) ) {
				self::remove_tree( $path );
			} else {
				unlink( $path );
			}
		}
		rmdir( $dir );
	}

	/**
	 * Forget the singleton's cached request and client IP so the next call re-reads $_SERVER.
	 */
	protected function reset_request(): void {
		$ref = new \ReflectionClass( Plugin::class );
		foreach ( array( 'country_logged', 'foreign_basic_logged' ) as $flag ) {
			$ref->getProperty( $flag )->setValue( $this->plugin, false );
		}
		$ref->getProperty( 'auth_stack' )->setValue( $this->plugin, array() );
		$ref->getProperty( 'own_origins_cache' )->setValue( $this->plugin, array() );
		$ref->getProperty( 'suspended_by' )->setValue( $this->plugin, 0 );
		$ref->getProperty( 'early_failures' )->setValue( $this->plugin, 0 );
		foreach ( array( 'request', 'client_ip', 'guard', 'geo', 'geo_peer_trusted', 'auth_refusal', 'basic_auth_editor' ) as $prop ) {
			// Private properties are writable through reflection since PHP 8.1.
			$ref->getProperty( $prop )->setValue( $this->plugin, null );
		}
	}

	/**
	 * Pretend the next request looks like this.
	 *
	 * @param array<string, string> $server Extra $_SERVER values.
	 * @param array<string, mixed>  $get    $_GET.
	 * @param array<string, mixed>  $post   $_POST.
	 */
	protected function fake_request( array $server = array(), array $get = array(), array $post = array() ): void {
		$_SERVER  = array_merge(
			$_SERVER,
			array(
				'REMOTE_ADDR'     => '203.0.113.9',
				'REQUEST_METHOD'  => 'GET',
				'REQUEST_URI'     => '/',
				'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) Test',
			),
			$server
		);
		$_GET     = $get;
		$_POST    = $post;
		$_REQUEST = array_merge( $get, $post );
		$this->reset_request();
		$this->plugin->reload_settings();
	}

	/**
	 * Replace settings (merged over the defaults, then sanitised and stored).
	 *
	 * @param array<string, mixed> $overrides Nested overrides.
	 */
	protected function set_settings( array $overrides ): void {
		$values = Settings::sanitize( array_replace_recursive( Settings::defaults(), $overrides ) );
		update_option( Settings::OPTION, $values, true );
		$this->plugin->reload_settings();
	}

	/**
	 * Mail captured by the test library's mock mailer.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	protected function sent_mail(): array {
		$mailer = tests_retrieve_phpmailer_instance();
		return $mailer ? $mailer->mock_sent : array();
	}

	/** Forget captured mail. */
	protected function clear_mail(): void {
		reset_phpmailer_instance();
	}

	/**
	 * Run a callback that redirects, and return where to.
	 *
	 * @param callable $fn Code that should end in wp_redirect()/wp_safe_redirect().
	 */
	protected function redirect_of( callable $fn ): Redirected {
		$thrower = static function ( $location, $status = 302 ) {
			throw new Redirected( (string) $location, (int) $status );
		};
		add_filter( 'wp_redirect', $thrower, 1, 2 );
		try {
			$fn();
		} catch ( Redirected $r ) {
			return $r;
		} finally {
			remove_filter( 'wp_redirect', $thrower, 1 );
		}
		$this->fail( 'Expected a redirect, but none happened.' );
	}

	/**
	 * Run a callback that must end in wp_die(), and return the exception.
	 *
	 * @param callable $fn Code under test.
	 */
	protected function die_of( callable $fn ): \WPDieException {
		try {
			$fn();
		} catch ( \WPDieException $e ) {
			return $e;
		}
		$this->fail( 'Expected wp_die(), but the code carried on.' );
	}

	/**
	 * Real DDL for this test: no CREATE/DROP TEMPORARY rewriting. The schema is
	 * rebuilt in tear-down. DDL commits implicitly, so rows written earlier in
	 * the test are cleaned up there too.
	 */
	protected function use_real_ddl(): void {
		$this->ddl_test = true;
		remove_filter( 'query', array( $this, '_create_temporary_tables' ) );
		remove_filter( 'query', array( $this, '_drop_temporary_tables' ) );
	}

	/**
	 * Put the three tables and the plugin's persistent state back after a DDL
	 * test. DDL commits implicitly, so anything the test wrote before it (the
	 * settings option, cron events, transients) is already permanent.
	 */
	private function restore_schema(): void {
		global $wpdb;
		$this->ddl_test = false;
		$wpdb->query( 'ROLLBACK' );
		// The object cache still holds values the rollback just discarded.
		wp_cache_flush();
		Installer::create_tables();
		foreach ( array( 'bouncer_log', 'bouncer_geo', 'bouncer_traffic', 'bouncer_counters' ) as $table ) {
			$wpdb->query( "DELETE FROM {$wpdb->prefix}{$table}" ); // phpcs:ignore WordPress.DB
		}
		update_option( Settings::OPTION, Settings::defaults(), true );
		update_option( Installer::DB_VERSION_OPTION, Installer::DB_VERSION, true );
		foreach ( array( UploadsGuard::STATE_OPTION, UploadsGuard::PROBE_OPTION, Plugin::GEO_META_OPTION, GeoImport::STATE_OPTION, RedactionMigration::STATE_OPTION, RedactionMigration::LOCK_OPTION ) as $option ) {
			delete_option( $option );
		}
		// Transients written by the plugin (counters, bans, alert throttle).
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_wpb\\_%' OR option_name LIKE '\\_transient\\_timeout\\_wpb\\_%'" ); // phpcs:ignore WordPress.DB
		wp_clear_scheduled_hook( Installer::CRON_HOOK );
		wp_clear_scheduled_hook( TrafficRecorder::PURGE_HOOK );
		wp_clear_scheduled_hook( UploadsGuard::CHECK_HOOK );
		Installer::schedule();
		wp_cache_flush();
		$wpdb->query( 'COMMIT' );
	}

	/**
	 * Does a table exist (permanent tables only)?
	 *
	 * @param string $table Full table name.
	 */
	protected function table_exists( string $table ): bool {
		global $wpdb;
		return $table === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) );
	}

	/**
	 * Column names of a table, in order.
	 *
	 * @param string $table Full table name.
	 * @return string[]
	 */
	protected function columns_of( string $table ): array {
		global $wpdb;
		return array_map( 'strval', (array) $wpdb->get_col( "SHOW COLUMNS FROM {$table}" ) ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Index name => ordered column list.
	 *
	 * @param string $table Full table name.
	 * @return array<string, string[]>
	 */
	protected function indexes_of( string $table ): array {
		global $wpdb;
		$out = array();
		foreach ( (array) $wpdb->get_results( "SHOW INDEX FROM {$table}", ARRAY_A ) as $row ) { // phpcs:ignore WordPress.DB
			$out[ $row['Key_name'] ][ (int) $row['Seq_in_index'] ] = $row['Column_name'];
		}
		return array_map( 'array_values', $out );
	}
}
