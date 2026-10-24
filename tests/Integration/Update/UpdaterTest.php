<?php
/**
 * Updater against WordPress's real update filters, with HTTP mocked.
 *
 * Nothing here touches the network: every request is answered by a
 * pre_http_request filter.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Update;

use WPBouncer\Plugin;
use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Update\Updater;

/**
 * @covers \WPBouncer\Update\Updater
 */
final class UpdaterTest extends IntegrationTestCase {

	private const PACKAGE = 'https://github.com/jimhstew/wp-bouncer/releases/download/v9.9.9/wp-bouncer-9.9.9.zip';

	/** @var Updater */
	private $updater;

	/** @var array<int, string> URLs requested. */
	private $requests = array();

	/** @var string Bytes served for the zip. */
	private $zip_bytes = "PK-fake-zip-bytes";

	public function set_up() {
		parent::set_up();
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$this->updater  = new Updater( WP_BOUNCER_FILE );
		$this->requests = array();
		delete_site_transient( Updater::CACHE );
	}

	/**
	 * @param array<string, string> $override Fields to override in update.json.
	 */
	private function manifest_json( array $override = array() ): string {
		return (string) wp_json_encode(
			array_merge(
				array(
					'version'      => '9.9.9',
					'package'      => self::PACKAGE,
					'sha256'       => hash( 'sha256', $this->zip_bytes ),
					'requires'     => '5.8',
					'requires_php' => '7.4',
					'tested'       => '7.1',
					'released'     => '2026-10-20',
					'changelog'    => "### Added\n- A **bold** thing with `code`.",
				),
				$override
			)
		);
	}

	/**
	 * Answer the manifest and zip requests.
	 *
	 * @param string|int|\WP_Error $manifest The manifest body, an HTTP status, or an error.
	 * @param string|int|\WP_Error $zip      The zip body, an HTTP status, or an error.
	 */
	private function serve( $manifest, $zip = null ): void {
		add_filter(
			'pre_http_request',
			function ( $pre, $args, $url ) use ( $manifest, $zip ) {
				$this->requests[] = $url;
				$answer           = false !== strpos( $url, '.zip' ) ? $zip : $manifest;
				if ( null === $answer ) {
					return new \WP_Error( 'unexpected', 'Unexpected request to ' . $url );
				}
				if ( $answer instanceof \WP_Error ) {
					return $answer;
				}
				$code = is_int( $answer ) ? $answer : 200;
				$body = is_int( $answer ) ? '' : $answer;
				if ( ! empty( $args['stream'] ) && ! empty( $args['filename'] ) ) {
					file_put_contents( $args['filename'], $body );
				}
				return array(
					'headers'  => array(),
					'body'     => ! empty( $args['stream'] ) ? '' : $body,
					'response' => array( 'code' => $code, 'message' => '' ),
					'cookies'  => array(),
					'filename' => $args['filename'] ?? null,
				);
			},
			10,
			3
		);
	}

	/* ---------------- registration ---------------- */

	public function test_register_adds_the_update_filters_and_actions(): void {
		$this->updater->register();

		$this->assertSame( 10, has_filter( 'update_plugins_github.com', array( $this->updater, 'filter_update' ) ) );
		$this->assertSame( 20, has_filter( 'plugins_api', array( $this->updater, 'filter_plugin_info' ) ) );
		$this->assertSame( 10, has_filter( 'upgrader_pre_download', array( $this->updater, 'filter_pre_download' ) ) );
		$this->assertNotFalse( has_action( 'upgrader_process_complete', array( $this->updater, 'forget' ) ) );
		$this->assertNotFalse( has_action( 'load-update-core.php', array( $this->updater, 'maybe_forget_on_force_check' ) ) );
	}

	public function test_default_urls_are_the_github_release_urls(): void {
		$this->assertSame( 'https://github.com/jimhstew/wp-bouncer', Updater::repository_url() );
		$this->assertSame( 'https://github.com/jimhstew/wp-bouncer/releases/latest/download/update.json', Updater::manifest_url() );
		$this->assertSame( 'https://github.com/jimhstew/wp-bouncer/releases/download/', Updater::package_prefix() );
	}

	public function test_source_filters_are_ignored_without_the_constant(): void {
		add_filter( 'wp_bouncer_update_manifest_url', static function () {
			return 'http://127.0.0.1:9/update.json';
		} );
		add_filter( 'wp_bouncer_update_package_prefix', static function () {
			return 'http://127.0.0.1:9/';
		} );
		$this->assertFalse( Updater::source_filters_allowed() );
		$this->assertSame( 'https://github.com/jimhstew/wp-bouncer/releases/latest/download/update.json', Updater::manifest_url() );
		$this->assertSame( 'https://github.com/jimhstew/wp-bouncer/releases/download/', Updater::package_prefix() );
	}

	public function test_is_disabled_reads_the_constant(): void {
		$this->assertFalse( Updater::is_disabled() );
	}

	/* ---------------- manifest fetch and cache ---------------- */

	public function test_manifest_is_fetched_parsed_and_cached(): void {
		$this->serve( $this->manifest_json() );

		$m = $this->updater->manifest();

		$this->assertNotNull( $m );
		$this->assertSame( '9.9.9', $m->version() );
		$this->assertSame( self::PACKAGE, $m->package() );
		$this->assertSame( array( Updater::manifest_url() ), $this->requests );

		$this->updater->manifest();
		$this->assertCount( 1, $this->requests, 'second call comes from the cache' );
		$this->assertSame( '', Updater::last_error() );
	}

	public function test_fresh_skips_the_cache(): void {
		$this->serve( $this->manifest_json() );
		$this->updater->manifest();

		$this->updater->manifest( true );

		$this->assertCount( 2, $this->requests );
	}

	public function test_the_request_identifies_the_plugin_and_sends_no_site_data(): void {
		$seen = null;
		add_filter(
			'pre_http_request',
			function ( $pre, $args ) use ( &$seen ) {
				$seen = $args;
				return array( 'headers' => array(), 'body' => '{}', 'response' => array( 'code' => 404, 'message' => '' ), 'cookies' => array(), 'filename' => null );
			},
			10,
			2
		);

		$this->updater->manifest();

		$this->assertSame( 'WP-Bouncer/' . Plugin::VERSION, $seen['user-agent'] );
		$this->assertStringNotContainsString( home_url(), wp_json_encode( $seen ) );
	}

	public function test_an_http_error_is_remembered_for_the_error_ttl(): void {
		$this->serve( new \WP_Error( 'http_request_failed', 'cURL error 6: Could not resolve host' ) );

		$this->assertNull( $this->updater->manifest() );
		$this->assertNull( $this->updater->manifest() );

		$this->assertCount( 1, $this->requests, 'no hammering GitHub after a failure' );
		$this->assertStringContainsString( 'Could not resolve host', Updater::last_error() );
		$ttl = (int) get_site_option( '_site_transient_timeout_' . Updater::CACHE ) - time(); // sitemeta on multisite.
		$this->assertEqualsWithDelta( HOUR_IN_SECONDS, $ttl, 5 );
	}

	public function test_a_404_is_an_error(): void {
		$this->serve( 404 );

		$this->assertNull( $this->updater->manifest() );
		$this->assertSame( 'HTTP 404', Updater::last_error() );
	}

	public function test_a_200_with_a_bad_body_is_an_error(): void {
		$this->serve( 'this is not json' );

		$this->assertNull( $this->updater->manifest() );
		$this->assertSame( 'invalid update.json', Updater::last_error() );
	}

	public function test_a_manifest_pointing_outside_the_repository_is_rejected(): void {
		$this->serve( $this->manifest_json( array( 'package' => 'https://evil.example/releases/download/v9/wp-bouncer.zip' ) ) );

		$this->assertNull( $this->updater->manifest() );
		$this->assertSame( 'invalid update.json', Updater::last_error() );
	}

	public function test_a_manifest_with_a_malformed_sha256_is_rejected(): void {
		$this->serve( $this->manifest_json( array( 'sha256' => 'abc' ) ) );

		$this->assertNull( $this->updater->manifest() );
	}

	public function test_forget_and_the_upgrade_hook_drop_the_cache(): void {
		$this->serve( $this->manifest_json() );
		// Core's own listeners would run a full update check against api.wordpress.org.
		remove_all_actions( 'upgrader_process_complete' );
		$this->updater->register();
		$this->updater->manifest();
		$this->assertNotFalse( get_site_transient( Updater::CACHE ) );

		do_action( 'upgrader_process_complete', new \stdClass(), array( 'type' => 'plugin', 'action' => 'update', 'plugins' => array() ) );

		$this->assertFalse( get_site_transient( Updater::CACHE ) );
	}

	public function test_force_check_clears_the_cache_only_for_users_who_can_update_plugins(): void {
		$this->serve( $this->manifest_json() );
		$this->updater->manifest();

		$_GET['force-check'] = '1';
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );
		$this->updater->maybe_forget_on_force_check();
		$this->assertNotFalse( get_site_transient( Updater::CACHE ), 'subscriber cannot clear it' );

		unset( $_GET['force-check'] );
		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( is_multisite() ) {
			grant_super_admin( $admin ); // Only super admins can update plugins on a network.
		}
		wp_set_current_user( $admin );
		$this->updater->maybe_forget_on_force_check();
		$this->assertNotFalse( get_site_transient( Updater::CACHE ), 'no force-check parameter, nothing to do' );

		$_GET['force-check'] = '1';
		$this->updater->maybe_forget_on_force_check();
		$this->assertFalse( get_site_transient( Updater::CACHE ) );
	}

	/* ---------------- update_plugins filter ---------------- */

	public function test_filter_update_offers_the_new_version(): void {
		$this->serve( $this->manifest_json() );

		$update = $this->updater->filter_update( false, array(), plugin_basename( WP_BOUNCER_FILE ) );

		$this->assertSame( 'wp-bouncer', $update['slug'] );
		$this->assertSame( '9.9.9', $update['version'] );
		$this->assertSame( self::PACKAGE, $update['package'] );
		$this->assertSame( '5.8', $update['requires'] );
		$this->assertSame( '7.4', $update['requires_php'] );
		$this->assertSame( '7.1', $update['tested'] );
		$this->assertSame( 'https://github.com/jimhstew/wp-bouncer', $update['url'] );
	}

	public function test_filter_update_is_wired_to_wordpress_through_the_host_filter(): void {
		$this->serve( $this->manifest_json() );
		$this->updater->register();

		$update = apply_filters( 'update_plugins_github.com', false, array(), plugin_basename( WP_BOUNCER_FILE ), array() );

		$this->assertSame( '9.9.9', $update['version'] );
	}

	public function test_filter_update_ignores_other_plugins_on_the_same_host(): void {
		$this->serve( $this->manifest_json() );
		$other = array( 'slug' => 'other', 'version' => '1.0' );

		$this->assertSame( $other, $this->updater->filter_update( $other, array(), 'other/other.php' ) );
		$this->assertFalse( $this->updater->filter_update( false, array(), 'other/other.php' ) );
		$this->assertSame( array(), $this->requests, 'no request for somebody else\'s plugin' );
	}

	public function test_filter_update_leaves_the_value_alone_when_the_check_failed(): void {
		$this->serve( new \WP_Error( 'x', 'down' ) );

		$this->assertFalse( $this->updater->filter_update( false, array(), plugin_basename( WP_BOUNCER_FILE ) ) );
	}

	public function test_an_older_or_equal_release_is_still_reported_for_the_auto_update_toggle(): void {
		$this->serve( $this->manifest_json( array( 'version' => Plugin::VERSION, 'package' => str_replace( '9.9.9', Plugin::VERSION, self::PACKAGE ) ) ) );

		$update = $this->updater->filter_update( false, array(), plugin_basename( WP_BOUNCER_FILE ) );

		$this->assertSame( Plugin::VERSION, $update['version'] );
		$this->assertFalse( version_compare( $update['version'], Plugin::VERSION, '>' ), 'WordPress sees no newer version, so it lists the plugin under "no update"' );
	}

	/* ---------------- plugins_api ---------------- */

	public function test_plugin_info_describes_the_release(): void {
		$this->serve( $this->manifest_json() );

		$info = $this->updater->filter_plugin_info( false, 'plugin_information', (object) array( 'slug' => 'wp-bouncer' ) );

		$this->assertSame( 'WP Bouncer', $info->name );
		$this->assertSame( '9.9.9', $info->version );
		$this->assertSame( self::PACKAGE, $info->download_link );
		$this->assertSame( '2026-10-20', $info->last_updated );
		$this->assertStringContainsString( '<strong>bold</strong>', $info->sections['changelog'] );
		$this->assertStringContainsString( '<code>code</code>', $info->sections['changelog'] );
		$this->assertStringContainsString( 'https://github.com/jimhstew/wp-bouncer', $info->sections['description'] );
	}

	public function test_plugin_info_without_a_changelog_links_to_the_releases_page(): void {
		$this->serve( $this->manifest_json( array( 'changelog' => '' ) ) );

		$info = $this->updater->filter_plugin_info( false, 'plugin_information', (object) array( 'slug' => 'wp-bouncer' ) );

		$this->assertStringContainsString( 'releases', $info->sections['changelog'] );
	}

	public function test_plugin_info_escapes_markup_from_the_manifest(): void {
		$this->serve( $this->manifest_json( array( 'changelog' => '- <script>alert(1)</script> done' ) ) );

		$info = $this->updater->filter_plugin_info( false, 'plugin_information', (object) array( 'slug' => 'wp-bouncer' ) );

		$this->assertStringNotContainsString( '<script>', $info->sections['changelog'] );
	}

	public function test_plugin_info_passes_through_other_slugs_actions_and_bad_args(): void {
		$this->serve( $this->manifest_json() );

		$this->assertFalse( $this->updater->filter_plugin_info( false, 'plugin_information', (object) array( 'slug' => 'akismet' ) ) );
		$this->assertFalse( $this->updater->filter_plugin_info( false, 'query_plugins', (object) array( 'slug' => 'wp-bouncer' ) ) );
		$this->assertFalse( $this->updater->filter_plugin_info( false, 'plugin_information', 'wp-bouncer' ) );
		$this->assertSame( array(), $this->requests );
	}

	public function test_plugin_info_is_wired_through_plugins_api(): void {
		$this->serve( $this->manifest_json() );
		$this->updater->register();
		require_once ABSPATH . 'wp-admin/includes/plugin-install.php';

		$info = plugins_api( 'plugin_information', array( 'slug' => 'wp-bouncer' ) );

		$this->assertIsObject( $info );
		$this->assertSame( '9.9.9', $info->version );
	}

	/* ---------------- download and checksum ---------------- */

	public function test_pre_download_returns_the_verified_zip(): void {
		$this->serve( $this->manifest_json(), $this->zip_bytes );

		$file = $this->updater->filter_pre_download( false, self::PACKAGE, new \stdClass(), array() );

		$this->assertIsString( $file );
		$this->assertFileExists( $file );
		$this->assertSame( $this->zip_bytes, file_get_contents( $file ) );
		unlink( $file );
	}

	public function test_pre_download_refuses_a_zip_with_the_wrong_sha256(): void {
		$this->serve( $this->manifest_json(), 'TAMPERED BYTES' );

		$result = $this->updater->filter_pre_download( false, self::PACKAGE, new \stdClass(), array() );

		$this->assertWPError( $result );
		$this->assertSame( 'wp_bouncer_checksum', $result->get_error_code() );
		$this->assertStringContainsString( hash( 'sha256', $this->zip_bytes ), $result->get_error_message(), 'names the expected hash' );
		$this->assertStringContainsString( hash( 'sha256', 'TAMPERED BYTES' ), $result->get_error_message(), 'and the one it got' );
	}

	public function test_a_refused_download_leaves_no_temp_file_behind(): void {
		$this->serve( $this->manifest_json(), 'TAMPERED BYTES' );
		$before = glob( get_temp_dir() . '*.tmp' ) ?: array();

		$this->updater->filter_pre_download( false, self::PACKAGE, new \stdClass(), array() );

		$after = glob( get_temp_dir() . '*.tmp' ) ?: array();
		$this->assertSame( array(), array_diff( $after, $before ) );
	}

	public function test_sha256_comparison_is_case_insensitive_for_the_manifest(): void {
		$this->serve( $this->manifest_json( array( 'sha256' => strtoupper( hash( 'sha256', $this->zip_bytes ) ) ) ), $this->zip_bytes );

		$file = $this->updater->filter_pre_download( false, self::PACKAGE, new \stdClass(), array() );

		$this->assertIsString( $file );
		unlink( $file );
	}

	public function test_pre_download_ignores_packages_that_are_not_ours(): void {
		$this->serve( $this->manifest_json(), $this->zip_bytes );

		$this->assertFalse( $this->updater->filter_pre_download( false, 'https://downloads.wordpress.org/plugin/akismet.zip', new \stdClass(), array() ) );
		$this->assertSame( 'already/handled.zip', $this->updater->filter_pre_download( 'already/handled.zip', self::PACKAGE, new \stdClass(), array() ) );
		$this->assertFalse( $this->updater->filter_pre_download( false, array( 'not a string' ), new \stdClass(), array() ) );
		$this->assertSame( array(), $this->requests );
	}

	public function test_pre_download_refuses_a_package_that_is_not_the_one_in_the_manifest(): void {
		$this->serve( $this->manifest_json(), $this->zip_bytes );
		$other = 'https://github.com/jimhstew/wp-bouncer/releases/download/v1.0.0/wp-bouncer-1.0.0.zip';

		$result = $this->updater->filter_pre_download( false, $other, new \stdClass(), array() );

		$this->assertWPError( $result );
		$this->assertSame( 'wp_bouncer_update_changed', $result->get_error_code() );
		$this->assertNotContains( $other, $this->requests, 'the foreign zip is never downloaded' );
	}

	public function test_pre_download_rechecks_a_stale_cached_manifest_once(): void {
		// The cache names 9.9.8; GitHub now says 9.9.9, which is what WordPress was told to download.
		set_site_transient( Updater::CACHE, array( 'json' => $this->manifest_json( array( 'version' => '9.9.8', 'package' => str_replace( '9.9.9', '9.9.8', self::PACKAGE ) ) ) ), HOUR_IN_SECONDS );
		$this->serve( $this->manifest_json(), $this->zip_bytes );

		$file = $this->updater->filter_pre_download( false, self::PACKAGE, new \stdClass(), array() );

		$this->assertIsString( $file );
		unlink( $file );
	}

	public function test_pre_download_reports_a_failed_download(): void {
		$this->serve( $this->manifest_json(), 404 );

		$result = $this->updater->filter_pre_download( false, self::PACKAGE, new \stdClass(), array() );

		$this->assertWPError( $result );
		$this->assertNotSame( 'wp_bouncer_checksum', $result->get_error_code() );
	}

	public function test_pre_download_gives_progress_feedback_when_the_skin_supports_it(): void {
		$this->serve( $this->manifest_json(), $this->zip_bytes );
		$skin     = new class() {
			public $messages = array();
			public function feedback( $string, ...$args ) {
				$this->messages[] = $string;
			}
		};
		$upgrader = (object) array( 'skin' => $skin );

		$file = $this->updater->filter_pre_download( false, self::PACKAGE, $upgrader, array() );

		$this->assertSame( array( 'downloading_package' ), $skin->messages );
		unlink( $file );
	}

	public function test_a_manifest_whose_package_is_not_the_exact_release_url_is_ignored(): void {
		$this->serve( $this->manifest_json( array( 'package' => 'https://github.com/jimhstew/wp-bouncer/releases/download/v9.9.9/../../../../evil/x/raw/wp-bouncer-9.9.9.zip' ) ) );

		$this->assertNull( $this->updater->manifest() );
		$this->assertFalse( $this->updater->filter_update( false, array(), plugin_basename( WP_BOUNCER_FILE ) ) );
	}
}
