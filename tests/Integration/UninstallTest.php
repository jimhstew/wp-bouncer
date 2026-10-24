<?php
/**
 * wp-bouncer/uninstall.php, run the way WordPress runs it.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration;

use WPBouncer\Geo\GeoImport;
use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Installer;
use WPBouncer\Plugin;
use WPBouncer\Settings;
use WPBouncer\Traffic\TrafficRecorder;
use WPBouncer\Update\Updater;

/**
 * Includes the uninstall file in a function scope with WP_UNINSTALL_PLUGIN defined
 * (a PHP constant; it stays defined for the process, which is harmless: only
 * uninstall.php looks at it).
 */
final class UninstallTest extends IntegrationTestCase {

	public function set_up() {
		parent::set_up();
		$this->use_real_ddl();
	}

	/** Run uninstall.php. */
	private function uninstall(): void {
		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', plugin_basename( WP_BOUNCER_FILE ) );
		}
		$run = static function (): void {
			global $wpdb;
			include WP_BOUNCER_DIR . '/uninstall.php';
		};
		$run();
	}

	/** Put data of every kind in place. */
	private function populate(): void {
		global $wpdb;
		update_option( Settings::OPTION, Settings::defaults() );
		update_option( Installer::DB_VERSION_OPTION, Installer::DB_VERSION );
		update_option( Plugin::GEO_META_OPTION, array( 'rows' => 3 ) );
		set_site_transient( Updater::CACHE, array( 'error' => 'x' ), HOUR_IN_SECONDS );
		$this->plugin->log()->record( array( 'ip' => '198.51.100.1' ) );
		$this->plugin->traffic_log()->record( array( 'ip' => '198.51.100.1' ) );
		$this->plugin->geo_database()->insert_batch( array( array( 'from' => str_repeat( '0', 31 ) . '1', 'to' => str_repeat( '0', 31 ) . '2', 'country' => 'AU' ) ) );
		( new \WPBouncer\Storage\TableCounter() )->add_or_increment( 'login_n:198.51.100.1', 600 );
		update_option( \WPBouncer\Storage\RedactionMigration::STATE_OPTION, array( 'log' => 5 ), false );
		wp_schedule_single_event( time() + 60, \WPBouncer\Storage\RedactionMigration::HOOK );
		$this->plugin->store()->set( 'ban:1', 1, 600 );
		$this->plugin->store()->increment( 'count:1', 600 );
		set_transient( 'unrelated_transient', 'keep me', 600 );
		update_option( 'unrelated_option', 'keep me' );
		wp_schedule_event( time() + 60, 'daily', Installer::CRON_HOOK );
		wp_schedule_event( time() + 60, 'hourly', TrafficRecorder::PURGE_HOOK );
		wp_schedule_single_event( time() + 60, UploadsGuard::CHECK_HOOK );
		$wpdb->query( 'COMMIT' );
	}

	public function test_it_drops_all_four_tables(): void {
		global $wpdb;
		$this->populate();

		$this->uninstall();

		foreach ( array( 'bouncer_log', 'bouncer_geo', 'bouncer_traffic', 'bouncer_counters' ) as $t ) {
			$this->assertFalse( $this->table_exists( $wpdb->prefix . $t ), $t );
		}
	}

	public function test_it_leaves_other_tables_alone(): void {
		global $wpdb;
		$this->populate();

		$this->uninstall();

		$this->assertTrue( $this->table_exists( $wpdb->options ) );
		$this->assertTrue( $this->table_exists( $wpdb->users ) );
	}

	public function test_it_deletes_the_options(): void {
		$this->populate();
		update_option( UploadsGuard::STATE_OPTION, array( 'ok' => true ) );
		update_option( UploadsGuard::PROBE_OPTION, array( 'result' => 'protected' ) );

		$this->uninstall();

		foreach ( array( Settings::OPTION, Installer::DB_VERSION_OPTION, Plugin::GEO_META_OPTION, GeoImport::STATE_OPTION, UploadsGuard::STATE_OPTION, UploadsGuard::PROBE_OPTION ) as $option ) {
			$this->assertFalse( get_option( $option ), $option );
		}
		$this->assertFalse( get_site_transient( Updater::CACHE ) );
		$this->assertSame( 'keep me', get_option( 'unrelated_option' ) );
	}

	public function test_it_deletes_counters_lockouts_and_bans_but_not_other_transients(): void {
		global $wpdb;
		$this->populate();
		$this->assertGreaterThan( 0, (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_wpb\\_%'" ) ); // phpcs:ignore WordPress.DB

		$this->uninstall();

		$this->assertSame( '0', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_wpb\\_%' OR option_name LIKE '\\_transient\\_timeout\\_wpb\\_%'" ) ); // phpcs:ignore WordPress.DB
		$this->assertSame( 'keep me', get_transient( 'unrelated_transient' ) );
	}

	public function test_it_clears_every_cron_hook(): void {
		$this->populate();
		$this->assertNotFalse( wp_next_scheduled( Installer::CRON_HOOK ) );

		$this->uninstall();

		$this->assertFalse( wp_next_scheduled( Installer::CRON_HOOK ) );
		$this->assertFalse( wp_next_scheduled( TrafficRecorder::PURGE_HOOK ) );
		$this->assertFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ) );
		$this->assertFalse( wp_next_scheduled( \WPBouncer\Storage\RedactionMigration::HOOK ) );
		$this->assertFalse( get_option( \WPBouncer\Storage\RedactionMigration::STATE_OPTION ) );
	}

	public function test_it_removes_our_htaccess_block_but_not_the_owners_lines(): void {
		file_put_contents( $this->uploads_dir . '/.htaccess', "Options -Indexes\n" );
		UploadsGuard::write_block();
		$this->populate();

		$this->uninstall();

		$text = (string) file_get_contents( $this->uploads_dir . '/.htaccess' );
		$this->assertStringContainsString( 'Options -Indexes', $text );
		$this->assertStringNotContainsString( 'WP Bouncer', $text );
	}

	public function test_it_removes_an_unfinished_import_and_its_working_files(): void {
		$this->populate();
		( new GeoImport( $this->plugin->geo_database() ) )->start( dirname( __DIR__ ) . '/fixtures/geo-sample.csv', 'sample.csv' );
		$file = (string) get_option( GeoImport::STATE_OPTION )['file'];
		$this->assertFileExists( $file );
		$dir = $this->uploads_dir . '/wp-bouncer';
		$this->assertDirectoryExists( $dir );

		$this->uninstall();

		$this->assertFileDoesNotExist( $file );
		$this->assertDirectoryDoesNotExist( $dir, 'the working folder is removed once empty' );
		$this->assertFalse( get_option( GeoImport::STATE_OPTION ) );
	}

	public function test_it_survives_a_second_run_and_a_site_with_nothing_installed(): void {
		$this->uninstall();
		$this->uninstall();

		$this->assertFalse( get_option( Settings::OPTION ) );
	}

	public function test_it_does_nothing_unless_wordpress_is_uninstalling(): void {
		// Without WP_UNINSTALL_PLUGIN the file must exit before touching anything. A subprocess
		// is the only way to observe that, since exit would end this test run.
		$php  = escapeshellarg( PHP_BINARY );
		$file = escapeshellarg( WP_BOUNCER_DIR . '/uninstall.php' );
		$out  = array();
		exec( "{$php} -r " . escapeshellarg( "define('ABSPATH','/x/'); include {$file}; echo 'REACHED';" ) . ' 2>&1', $out );

		$this->assertStringNotContainsString( 'REACHED', implode( "\n", $out ) );
	}
}
