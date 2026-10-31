<?php
/**
 * wp-bouncer/uninstall.php, run the way WordPress runs it.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration;

use WPBouncer\Admin\DashboardWidget;
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
		// A real uninstall runs with the plugin inactive, so its hooks are not loaded.
		$this->without_settings_audit( $run );
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
		$this->plugin->geo_database()->insert_batch(
			array(
				array(
					'from'    => str_repeat( '0', 31 ) . '1',
					'to'      => str_repeat( '0', 31 ) . '2',
					'country' => 'AU',
				),
			)
		);
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

	/**
	 * One populated site, one uninstall (each real DDL statement is slow), checked from every angle.
	 * The assertion messages name the behaviour that failed.
	 */
	public function test_it_removes_everything_of_ours_and_nothing_else(): void {
		global $wpdb;
		$file = $this->uploads_dir . '/.htaccess';
		file_put_contents( $file, "Options -Indexes\n" );
		UploadsGuard::write_block();
		$this->populate();
		update_option( UploadsGuard::STATE_OPTION, array( 'ok' => true ) );
		update_option( UploadsGuard::PROBE_OPTION, array( 'result' => 'protected' ) );
		wp_schedule_single_event( time() + 60, 'wp_bouncer_old_wp_email' );
		$this->assertNotFalse( wp_next_scheduled( Installer::CRON_HOOK ), 'precondition: cron is scheduled' );
		$this->assertGreaterThan( 0, (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_wpb\\_%'" ), 'precondition: counters and bans exist' ); // phpcs:ignore WordPress.DB

		$ours   = array(
			'wpb_' . md5( 'ban:1' ),
			'wpb_ctrfb_' . md5( 'x' ),
			'wpb_flash_7',
			'wpb_alert_count',
			'wpb_alert_count_critical',
			'wpb_alert_count_settings',
			'wpb_alert_settings_notice',
			'wpb_alert_uncapped',
			DashboardWidget::TRANSIENT,
			'wp_bouncer_export_' . md5( 'abc' ),
			'wp_bouncer_erase_range_5',
			'wpb_map_' . str_repeat( 'a', 20 ),
			'wpb_map_lock',
			'wpb_map_thr_12',
		);
		update_option( 'wpb_map_keys', array( 'gen' => 2, 'keys' => array() ), false );
		update_option( 'wpb_map_gen', 2, false );
		update_option( 'wpb_map_lock', time() . '|abc', false );
		$others = array( 'wpb_map_' . str_repeat( 'a', 19 ), 'wpb_map_thr_x', 'wpb_notours', 'wpb_' . str_repeat( 'z', 32 ), 'other_wpb_' . md5( 'y' ), 'wp_bouncer_unrelated' );
		foreach ( array_merge( $ours, $others ) as $name ) {
			set_transient( $name, 'v', 600 );
		}
		$count = static function ( array $names ) use ( $wpdb ): int {
			$n = 0;
			foreach ( $names as $name ) {
				foreach ( array( '_transient_', '_transient_timeout_' ) as $prefix ) {
					$n += (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name = %s", $prefix . $name ) ); // phpcs:ignore WordPress.DB
				}
			}
			return $n;
		};
		$this->assertSame( 2 * count( $ours ), $count( $ours ), 'precondition: our transients exist' );

		$this->uninstall();

		// Tables.
		foreach ( array( 'bouncer_log', 'bouncer_geo', 'bouncer_traffic', 'bouncer_counters' ) as $t ) {
			$this->assertFalse( $this->table_exists( $wpdb->prefix . $t ), "table {$t} dropped" );
		}
		$this->assertTrue( $this->table_exists( $wpdb->options ), 'other tables left alone: options' );
		$this->assertTrue( $this->table_exists( $wpdb->users ), 'other tables left alone: users' );

		// Options.
		foreach ( array( Settings::OPTION, Installer::DB_VERSION_OPTION, Plugin::GEO_META_OPTION, GeoImport::STATE_OPTION, UploadsGuard::STATE_OPTION, UploadsGuard::PROBE_OPTION ) as $option ) {
			$this->assertFalse( get_option( $option ), "option {$option} deleted" );
		}
		$this->assertFalse( get_option( 'wpb_map_keys' ), 'threat map index deleted' );
		$this->assertFalse( get_option( 'wpb_map_gen' ), 'threat map generation deleted' );
		$this->assertFalse( get_option( 'wpb_map_lock' ), 'threat map lock deleted' );
		$this->assertFalse( get_site_transient( Updater::CACHE ), 'updater cache deleted' );
		$this->assertSame( 'keep me', get_option( 'unrelated_option' ), 'unrelated option kept' );

		// Transients.
		// Only the four look-alikes below that happen to start with wpb_ (8 rows with their timeouts) may match.
		$this->assertSame( 8, (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_wpb\\_%' OR option_name LIKE '\\_transient\\_timeout\\_wpb\\_%'" ), 'counters, lockouts and bans deleted' ); // phpcs:ignore WordPress.DB
		$this->assertSame( 'keep me', get_transient( 'unrelated_transient' ), 'unrelated transient kept' );
		$this->assertSame( 0, $count( $ours ), 'every one of ours is gone, with its timeout row' );
		$this->assertSame( 2 * count( $others ), $count( $others ), 'other plugins\' look-alikes stay' );

		// Cron.
		$this->assertFalse( wp_next_scheduled( 'wp_bouncer_old_wp_email' ), 'old-WordPress email event cleared' );
		$this->assertFalse( wp_next_scheduled( Installer::CRON_HOOK ), 'daily cron cleared' );
		$this->assertFalse( wp_next_scheduled( TrafficRecorder::PURGE_HOOK ), 'traffic purge cron cleared' );
		$this->assertFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ), 'uploads check cron cleared' );
		$this->assertFalse( wp_next_scheduled( \WPBouncer\Storage\RedactionMigration::HOOK ), 'redaction cron cleared' );
		$this->assertFalse( get_option( \WPBouncer\Storage\RedactionMigration::STATE_OPTION ), 'redaction state deleted' );

		// The .htaccess block.
		$text = (string) file_get_contents( $file );
		$this->assertStringContainsString( 'Options -Indexes', $text, 'the owner\'s .htaccess lines stay' );
		$this->assertStringNotContainsString( 'WP Bouncer', $text, 'our .htaccess block is removed' );
	}

	public function test_it_does_not_delete_a_working_file_outside_its_own_folder(): void {
		$outside = $this->uploads_dir . '/precious.csv';
		file_put_contents( $outside, 'x' );
		update_option( GeoImport::STATE_OPTION, array( 'file' => $outside ) );

		$this->uninstall();

		$this->assertFileExists( $outside );
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
