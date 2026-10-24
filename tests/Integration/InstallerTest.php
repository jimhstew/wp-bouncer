<?php
/**
 * Installer against a real database.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration;

use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Hardening\UploadsPolicy;
use WPBouncer\Installer;
use WPBouncer\Settings;
use WPBouncer\Traffic\TrafficRecorder;

/**
 * @covers \WPBouncer\Installer
 */
final class InstallerTest extends IntegrationTestCase {

	/** Drop the three tables for real (DDL), as on a site that never activated the plugin. */
	private function drop_tables(): void {
		global $wpdb;
		$this->use_real_ddl();
		foreach ( array( 'bouncer_log', 'bouncer_geo', 'bouncer_traffic' ) as $t ) {
			$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}{$t}" ); // phpcs:ignore WordPress.DB
		}
	}

	private function clear_cron(): void {
		wp_clear_scheduled_hook( Installer::CRON_HOOK );
		wp_clear_scheduled_hook( TrafficRecorder::PURGE_HOOK );
	}

	public function test_activate_creates_the_three_tables_with_expected_columns(): void {
		global $wpdb;
		$this->drop_tables();
		$this->assertFalse( $this->table_exists( $wpdb->prefix . 'bouncer_log' ) );

		Installer::activate();

		$this->assertSame(
			array( 'id', 'created_at', 'ip', 'country', 'rule', 'action', 'reason', 'method', 'uri', 'user_agent' ),
			$this->columns_of( $wpdb->prefix . 'bouncer_log' )
		);
		$this->assertSame(
			array( 'ip_from', 'ip_to', 'country' ),
			$this->columns_of( $wpdb->prefix . 'bouncer_geo' )
		);
		$this->assertSame(
			array( 'id', 'created_at', 'ip', 'method', 'uri', 'referrer', 'user_agent', 'client', 'status', 'user_id' ),
			$this->columns_of( $wpdb->prefix . 'bouncer_traffic' )
		);
	}

	public function test_activate_creates_the_expected_indexes(): void {
		global $wpdb;
		$this->drop_tables();
		Installer::activate();

		$log = $this->indexes_of( $wpdb->prefix . 'bouncer_log' );
		$this->assertSame( array( 'id' ), $log['PRIMARY'] );
		$this->assertSame( array( 'created_at' ), $log['created_at'] );
		$this->assertSame( array( 'ip' ), $log['ip'] );
		$this->assertSame( array( 'rule' ), $log['rule'] );

		$geo = $this->indexes_of( $wpdb->prefix . 'bouncer_geo' );
		$this->assertSame( array( 'ip_from' ), $geo['PRIMARY'] );

		$traffic = $this->indexes_of( $wpdb->prefix . 'bouncer_traffic' );
		$this->assertSame( array( 'id' ), $traffic['PRIMARY'] );
		foreach ( array( 'created_at', 'ip', 'client', 'status' ) as $col ) {
			$this->assertSame( array( $col ), $traffic[ $col ], "traffic index on {$col}" );
		}
	}

	public function test_activate_uses_the_documented_column_types(): void {
		global $wpdb;
		$this->drop_tables();
		Installer::activate();

		$types = array();
		foreach ( (array) $wpdb->get_results( "SHOW COLUMNS FROM {$wpdb->prefix}bouncer_geo", ARRAY_A ) as $row ) { // phpcs:ignore WordPress.DB
			$types[ $row['Field'] ] = strtolower( $row['Type'] );
		}
		$this->assertSame( 'char(32)', $types['ip_from'] );
		$this->assertSame( 'char(32)', $types['ip_to'] );
		$this->assertSame( 'char(2)', $types['country'] );

		$types = array();
		foreach ( (array) $wpdb->get_results( "SHOW COLUMNS FROM {$wpdb->prefix}bouncer_log", ARRAY_A ) as $row ) { // phpcs:ignore WordPress.DB
			$types[ $row['Field'] ] = strtolower( $row['Type'] );
		}
		$this->assertSame( 'varchar(2048)', $types['uri'] );
		$this->assertSame( 'varchar(45)', $types['ip'] );
		$this->assertSame( 'datetime', $types['created_at'] );
	}

	public function test_activate_records_db_version_and_default_settings(): void {
		$this->drop_tables();
		delete_option( Settings::OPTION );
		delete_option( Installer::DB_VERSION_OPTION );

		Installer::activate();

		$this->assertSame( Installer::DB_VERSION, get_option( Installer::DB_VERSION_OPTION ) );
		$this->assertSame( Settings::defaults(), get_option( Settings::OPTION ) );
	}

	public function test_activate_keeps_existing_settings(): void {
		$this->drop_tables();
		$custom         = Settings::defaults();
		$custom['mode'] = 'monitor';
		update_option( Settings::OPTION, $custom );

		Installer::activate();

		$this->assertSame( 'monitor', get_option( Settings::OPTION )['mode'] );
	}

	public function test_activate_schedules_both_jobs(): void {
		$this->drop_tables();
		$this->clear_cron();

		Installer::activate();

		$this->assertNotFalse( wp_next_scheduled( Installer::CRON_HOOK ) );
		$this->assertNotFalse( wp_next_scheduled( TrafficRecorder::PURGE_HOOK ) );
		$this->assertSame( 'daily', wp_get_schedule( Installer::CRON_HOOK ) );
		$this->assertSame( 'hourly', wp_get_schedule( TrafficRecorder::PURGE_HOOK ) );
	}

	public function test_create_tables_twice_is_harmless_and_keeps_rows(): void {
		global $wpdb;
		$this->drop_tables();
		Installer::create_tables();
		$wpdb->insert( $wpdb->prefix . 'bouncer_log', array( 'created_at' => '2026-01-01 00:00:00', 'ip' => '198.51.100.1' ) );

		Installer::create_tables();

		$this->assertSame( '1', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log" ) ); // phpcs:ignore WordPress.DB
		$this->assertSame( '', (string) $wpdb->last_error );
	}

	public function test_schedule_does_not_duplicate_events(): void {
		$this->clear_cron();

		Installer::schedule();
		$first = array( wp_next_scheduled( Installer::CRON_HOOK ), wp_next_scheduled( TrafficRecorder::PURGE_HOOK ) );
		Installer::schedule();

		$this->assertSame( $first, array( wp_next_scheduled( Installer::CRON_HOOK ), wp_next_scheduled( TrafficRecorder::PURGE_HOOK ) ) );
		$count = 0;
		foreach ( _get_cron_array() as $hooks ) {
			$count += isset( $hooks[ Installer::CRON_HOOK ] ) ? count( $hooks[ Installer::CRON_HOOK ] ) : 0;
		}
		$this->assertSame( 1, $count );
	}

	public function test_schedule_only_adds_the_missing_job(): void {
		$this->clear_cron();
		wp_schedule_event( time() + 100, 'daily', Installer::CRON_HOOK );
		$existing = wp_next_scheduled( Installer::CRON_HOOK );

		Installer::schedule();

		$this->assertSame( $existing, wp_next_scheduled( Installer::CRON_HOOK ) );
		$this->assertNotFalse( wp_next_scheduled( TrafficRecorder::PURGE_HOOK ) );
	}

	public function test_maybe_upgrade_from_version_1_adds_traffic_table_and_purge_job(): void {
		global $wpdb;
		$this->drop_tables();
		// A site on schema version 1: log and geo only, no purge job.
		Installer::create_tables();
		$wpdb->query( "DROP TABLE {$wpdb->prefix}bouncer_traffic" ); // phpcs:ignore WordPress.DB
		$wpdb->insert( $wpdb->prefix . 'bouncer_log', array( 'created_at' => '2026-01-01 00:00:00', 'ip' => '198.51.100.7' ) );
		update_option( Installer::DB_VERSION_OPTION, '1' );
		$this->clear_cron();
		$this->assertFalse( $this->table_exists( $wpdb->prefix . 'bouncer_traffic' ) );

		Installer::maybe_upgrade();

		$this->assertTrue( $this->table_exists( $wpdb->prefix . 'bouncer_traffic' ) );
		$this->assertSame( '2', get_option( Installer::DB_VERSION_OPTION ) );
		$this->assertNotFalse( wp_next_scheduled( TrafficRecorder::PURGE_HOOK ), 'purge job scheduled by the upgrade' );
		$this->assertSame( 'hourly', wp_get_schedule( TrafficRecorder::PURGE_HOOK ) );
		$this->assertSame( '1', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log" ), 'existing rows kept' ); // phpcs:ignore WordPress.DB
	}

	public function test_maybe_upgrade_runs_when_the_version_option_is_missing(): void {
		global $wpdb;
		$this->drop_tables();
		delete_option( Installer::DB_VERSION_OPTION );

		Installer::maybe_upgrade();

		$this->assertTrue( $this->table_exists( $wpdb->prefix . 'bouncer_log' ) );
		$this->assertSame( Installer::DB_VERSION, get_option( Installer::DB_VERSION_OPTION ) );
	}

	public function test_maybe_upgrade_does_nothing_when_current(): void {
		global $wpdb;
		$this->drop_tables();
		Installer::create_tables();
		$wpdb->query( "DROP TABLE {$wpdb->prefix}bouncer_traffic" ); // phpcs:ignore WordPress.DB
		$this->assertSame( Installer::DB_VERSION, get_option( Installer::DB_VERSION_OPTION ) );

		Installer::maybe_upgrade();

		$this->assertFalse( $this->table_exists( $wpdb->prefix . 'bouncer_traffic' ), 'no schema work when the version matches' );
	}

	public function test_deactivate_clears_cron_events(): void {
		wp_schedule_event( time() + 60, 'daily', Installer::CRON_HOOK );
		wp_schedule_event( time() + 60, 'hourly', TrafficRecorder::PURGE_HOOK );

		Installer::deactivate();

		$this->assertFalse( wp_next_scheduled( Installer::CRON_HOOK ) );
		$this->assertFalse( wp_next_scheduled( TrafficRecorder::PURGE_HOOK ) );
	}

	public function test_deactivate_removes_the_uploads_htaccess_block_but_keeps_other_lines(): void {
		$file = $this->uploads_dir . '/.htaccess';
		file_put_contents( $file, "# owner rule\nOptions -Indexes\n" );
		$this->assertTrue( UploadsGuard::write_block() );
		$this->assertTrue( UploadsGuard::block_present() );

		Installer::deactivate();

		$this->assertFalse( UploadsGuard::block_present() );
		$contents = (string) file_get_contents( $file );
		$this->assertStringContainsString( 'Options -Indexes', $contents );
		$this->assertStringNotContainsString( 'BEGIN ' . UploadsPolicy::MARKER, $contents );
		$this->assertFalse( get_option( UploadsGuard::STATE_OPTION ) );
	}

	public function test_deactivate_deletes_an_htaccess_that_only_held_our_block(): void {
		UploadsGuard::write_block();
		$this->assertFileExists( $this->uploads_dir . '/.htaccess' );

		Installer::deactivate();

		$this->assertFileDoesNotExist( $this->uploads_dir . '/.htaccess' );
	}

	public function test_deactivate_keeps_settings_and_tables(): void {
		global $wpdb;
		Installer::deactivate();

		$this->assertNotFalse( get_option( Settings::OPTION ) );
		$this->assertTrue( $this->table_exists( $wpdb->prefix . 'bouncer_log' ) );
	}
}
