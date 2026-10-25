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
use WPBouncer\Storage\RedactionMigration;
use WPBouncer\Traffic\TrafficRecorder;

/**
 * @covers \WPBouncer\Installer
 */
final class InstallerTest extends IntegrationTestCase {

	public function tear_down() {
		global $wpdb;
		parent::tear_down();
		// A DDL statement commits the rows the upgrade wrote, and the rollback in tear-down
		// would bring them back after the upgrade deleted them. Remove them for good.
		foreach ( array( Installer::LOCK_OPTION, Installer::FAILED_OPTION ) as $name ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", $name ) ); // phpcs:ignore WordPress.DB
			wp_cache_delete( $name, 'options' );
		}
		$wpdb->query( 'COMMIT' );
		wp_cache_delete( 'alloptions', 'options' );
		wp_cache_delete( 'notoptions', 'options' );
	}

	/**
	 * Drop plugin tables for real (DDL). Each DDL statement is slow on a durable server, so
	 * tests drop only the tables they need missing. All four: a site that never activated the plugin.
	 *
	 * @param string[] $tables Table names without the prefix.
	 */
	private function drop_tables( array $tables = array( 'bouncer_log', 'bouncer_geo', 'bouncer_traffic', 'bouncer_counters' ) ): void {
		global $wpdb;
		$this->use_real_ddl();
		foreach ( $tables as $t ) {
			$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}{$t}" ); // phpcs:ignore WordPress.DB
		}
	}

	private function clear_cron(): void {
		wp_clear_scheduled_hook( Installer::CRON_HOOK );
		wp_clear_scheduled_hook( TrafficRecorder::PURGE_HOOK );
		wp_clear_scheduled_hook( Installer::COUNTER_PURGE_HOOK );
		wp_clear_scheduled_hook( RedactionMigration::HOOK );
	}

	/**
	 * One fresh install (all four tables dropped, so the slow DDL runs once) checked from every angle.
	 * The labels name the behaviour that failed.
	 */
	public function test_activate_on_a_fresh_site_creates_tables_records_version_and_schedules_jobs(): void {
		global $wpdb;
		$this->drop_tables();
		delete_option( Settings::OPTION );
		delete_option( Installer::DB_VERSION_OPTION );
		$this->clear_cron();
		$this->assertFalse( $this->table_exists( $wpdb->prefix . 'bouncer_log' ), 'precondition: tables are gone' );

		Installer::activate();

		// Columns of the three tables.
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

		// Counters table.
		$this->assertSame( array( 'counter_key', 'hits', 'expires_at' ), $this->columns_of( $wpdb->prefix . 'bouncer_counters' ) );
		$indexes = $this->indexes_of( $wpdb->prefix . 'bouncer_counters' );
		$this->assertSame( array( 'counter_key' ), $indexes['PRIMARY'] );
		$this->assertSame( array( 'expires_at' ), $indexes['expires_at'] );
		$this->assertFalse( RedactionMigration::pending(), 'a fresh install has nothing to redact' );

		// Indexes.
		$log = $this->indexes_of( $wpdb->prefix . 'bouncer_log' );
		$this->assertSame( array( 'id' ), $log['PRIMARY'] );
		$this->assertSame( array( 'created_at' ), $log['created_at'] );
		$this->assertSame( array( 'ip' ), $log['ip'] );
		$this->assertSame( array( 'rule' ), $log['rule'] );

		$geo = $this->indexes_of( $wpdb->prefix . 'bouncer_geo' );
		$this->assertSame( array( 'ip_from' ), $geo['PRIMARY'] );

		$traffic = $this->indexes_of( $wpdb->prefix . 'bouncer_traffic' );
		$this->assertSame( array( 'id' ), $traffic['PRIMARY'] );
		foreach ( array( 'created_at', 'ip', 'client', 'status', 'user_id' ) as $col ) {
			$this->assertSame( array( $col ), $traffic[ $col ], "traffic index on {$col}" );
		}

		// Column types.
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

		// Version and default settings.
		$this->assertSame( Installer::DB_VERSION, get_option( Installer::DB_VERSION_OPTION ) );
		$this->assertSame( Settings::defaults(), get_option( Settings::OPTION ) );

		// Cron jobs.
		$this->assertNotFalse( wp_next_scheduled( Installer::CRON_HOOK ) );
		$this->assertNotFalse( wp_next_scheduled( TrafficRecorder::PURGE_HOOK ) );
		$this->assertSame( 'daily', wp_get_schedule( Installer::CRON_HOOK ) );
		$this->assertSame( 'hourly', wp_get_schedule( TrafficRecorder::PURGE_HOOK ) );
		$this->assertSame( 'hourly', wp_get_schedule( Installer::COUNTER_PURGE_HOOK ), 'expired login counters are purged hourly' );

		// Running create_tables again is harmless and keeps rows.
		$wpdb->insert(
			$wpdb->prefix . 'bouncer_log',
			array(
				'created_at' => '2026-01-01 00:00:00',
				'ip'         => '198.51.100.1',
			)
		);

		Installer::create_tables();

		$this->assertSame( '1', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log" ), 'create_tables twice keeps rows' ); // phpcs:ignore WordPress.DB
		$this->assertSame( '', (string) $wpdb->last_error, 'create_tables twice raises no error' );
	}

	public function test_activate_keeps_existing_settings(): void {
		$custom         = Settings::defaults();
		$custom['mode'] = 'monitor';
		update_option( Settings::OPTION, $custom );

		Installer::activate();

		$this->assertSame( 'monitor', get_option( Settings::OPTION )['mode'] );
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
		// A site on schema version 1: log and geo only, no purge job.
		$this->drop_tables( array( 'bouncer_traffic', 'bouncer_counters' ) );
		$wpdb->insert(
			$wpdb->prefix . 'bouncer_log',
			array(
				'created_at' => '2026-01-01 00:00:00',
				'ip'         => '198.51.100.7',
			)
		);
		update_option( Installer::DB_VERSION_OPTION, '1' );
		$this->clear_cron();
		$this->assertFalse( $this->table_exists( $wpdb->prefix . 'bouncer_traffic' ) );

		Installer::maybe_upgrade();

		$this->assertTrue( $this->table_exists( $wpdb->prefix . 'bouncer_traffic' ) );
		$this->assertSame( '3', get_option( Installer::DB_VERSION_OPTION ) );
		$this->assertNotFalse( wp_next_scheduled( TrafficRecorder::PURGE_HOOK ), 'purge job scheduled by the upgrade' );
		$this->assertSame( 'hourly', wp_get_schedule( TrafficRecorder::PURGE_HOOK ) );
		$this->assertSame( '1', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_log" ), 'existing rows kept' ); // phpcs:ignore WordPress.DB
	}

	public function test_maybe_upgrade_runs_when_the_version_option_is_missing(): void {
		global $wpdb;
		$this->drop_tables( array( 'bouncer_log', 'bouncer_traffic' ) );
		delete_option( Installer::DB_VERSION_OPTION );

		Installer::maybe_upgrade();

		$this->assertTrue( $this->table_exists( $wpdb->prefix . 'bouncer_log' ) );
		$this->assertSame( Installer::DB_VERSION, get_option( Installer::DB_VERSION_OPTION ) );
	}

	public function test_a_held_upgrade_lock_makes_maybe_upgrade_skip_dbdelta(): void {
		global $wpdb;
		$this->drop_tables( array( 'bouncer_log', 'bouncer_traffic' ) );
		delete_option( Installer::DB_VERSION_OPTION );
		add_option( Installer::LOCK_OPTION, (string) time(), '', false );

		Installer::maybe_upgrade();

		$this->assertFalse( $this->table_exists( $wpdb->prefix . 'bouncer_log' ), 'dbDelta did not run' );
		$this->assertFalse( get_option( Installer::DB_VERSION_OPTION ) );
		$this->assertNotFalse( get_option( Installer::LOCK_OPTION ), 'the holder keeps its lock' );
		delete_option( Installer::LOCK_OPTION );
	}

	public function test_a_stale_upgrade_lock_is_taken_over_and_released(): void {
		global $wpdb;
		$this->drop_tables( array( 'bouncer_log', 'bouncer_traffic' ) );
		delete_option( Installer::DB_VERSION_OPTION );
		add_option( Installer::LOCK_OPTION, (string) ( time() - HOUR_IN_SECONDS ), '', false );

		Installer::maybe_upgrade();

		$this->assertTrue( $this->table_exists( $wpdb->prefix . 'bouncer_log' ) );
		$this->assertSame( Installer::DB_VERSION, get_option( Installer::DB_VERSION_OPTION ) );
		$this->assertFalse( get_option( Installer::LOCK_OPTION ) );
	}

	public function test_a_failed_create_leaves_the_version_unchanged_so_the_upgrade_is_retried(): void {
		global $wpdb;
		$this->drop_tables( array( 'bouncer_traffic' ) );
		delete_option( Installer::DB_VERSION_OPTION );
		$break = static function ( $sql ) {
			return ( 0 === stripos( ltrim( (string) $sql ), 'CREATE TABLE' ) && false !== strpos( (string) $sql, 'bouncer_traffic' ) ) ? 'SELECT * FROM wpb_no_such_table_zz' : $sql;
		};
		add_filter( 'query', $break, 99 );
		$suppress = $wpdb->suppress_errors( true );

		Installer::maybe_upgrade();

		$wpdb->suppress_errors( $suppress );
		remove_filter( 'query', $break, 99 );
		$this->assertFalse( $this->table_exists( $wpdb->prefix . 'bouncer_traffic' ) );
		$this->assertFalse( get_option( Installer::DB_VERSION_OPTION ), 'version not recorded' );
		$this->assertNotFalse( get_option( Installer::LOCK_OPTION ), 'lock kept so requests do not re-run dbDelta' );
		$this->assertNotFalse( get_option( Installer::FAILED_OPTION ), 'failure recorded for the admin notice' );

		// A second request inside the TTL does not run dbDelta (the broken filter would count it).
		$runs = 0;
		$spy  = static function ( $sql ) use ( &$runs ) {
			if ( 0 === stripos( ltrim( (string) $sql ), 'CREATE TABLE' ) ) {
				++$runs;
			}
			return $sql;
		};
		add_filter( 'query', $spy, 1 );
		Installer::maybe_upgrade();
		$this->assertSame( 0, $runs, 'no dbDelta within the TTL' );
		$this->assertFalse( $this->table_exists( $wpdb->prefix . 'bouncer_traffic' ) );

		// After the TTL it retries and succeeds.
		update_option( Installer::LOCK_OPTION, (string) ( time() - HOUR_IN_SECONDS ) );
		Installer::maybe_upgrade();
		remove_filter( 'query', $spy, 1 );
		$this->assertGreaterThan( 0, $runs );
		$this->assertFalse( get_option( Installer::LOCK_OPTION ), 'lock released on success' );
		$this->assertFalse( get_option( Installer::FAILED_OPTION ), 'failure cleared' );

		$this->assertTrue( $this->table_exists( $wpdb->prefix . 'bouncer_traffic' ) );
		$this->assertSame( Installer::DB_VERSION, get_option( Installer::DB_VERSION_OPTION ) );
	}

	public function test_maybe_upgrade_does_nothing_when_current(): void {
		global $wpdb;
		$this->drop_tables( array( 'bouncer_traffic' ) );
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


	/** On the main site of a network only a network admin may remove the shared block. */
	private function as_network_admin(): void {
		if ( is_multisite() ) {
			$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
			grant_super_admin( $id );
			wp_set_current_user( $id );
		}
	}

	public function test_deactivate_removes_the_uploads_htaccess_block_but_keeps_other_lines(): void {
		$this->as_network_admin();
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
		$this->as_network_admin();
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

	public function test_maybe_upgrade_from_version_2_adds_counters_and_redacts_existing_rows(): void {
		global $wpdb;
		$this->drop_tables( array( 'bouncer_counters' ) );
		$wpdb->query( "ALTER TABLE {$wpdb->prefix}bouncer_traffic DROP INDEX user_id" ); // phpcs:ignore WordPress.DB
		delete_option( RedactionMigration::STATE_OPTION );
		update_option( Installer::DB_VERSION_OPTION, '2' );
		$this->clear_cron();

		$log     = $wpdb->prefix . 'bouncer_log';
		$traffic = $wpdb->prefix . 'bouncer_traffic';
		$login   = 'wpb_s10_user';
		$user_id = self::factory()->user->create( array( 'user_login' => $login ) );
		$rows    = array(
			array(
				'uri'    => '/?key=SECRET1&ok=1',
				'reason' => '',
				'rule'   => 'waf',
			),
			array(
				'uri'    => '/clean',
				'reason' => '',
				'rule'   => 'waf',
			),
			array(
				'uri'    => '/wp-login.php',
				'reason' => '5 failed logins (last username "hunter2-typo") – locked out for 60 min',
				'rule'   => 'login_lockout',
			),
			array(
				'uri'    => '/wp-login.php',
				'reason' => '5 failed logins (last username "' . $login . '") – locked out for 60 min',
				'rule'   => 'login_lockout',
			),
			array(
				'uri'    => '/wp-login.php',
				'reason' => 'Tried banned username "admin"',
				'rule'   => 'login_lockout',
			),
		);
		foreach ( $rows as $row ) {
			$wpdb->insert(
				$log,
				array_merge(
					array(
						'created_at' => '2026-01-01 00:00:00',
						'ip'         => '198.51.100.7',
					),
					$row
				)
			);
		}
		$wpdb->insert(
			$traffic,
			array(
				'created_at' => '2026-01-01 00:00:00',
				'ip'         => '198.51.100.7',
				'uri'        => '/?token=SECRET2',
				'referrer'   => 'https://example.org/?password=SECRET3&a=1',
			)
		);
		$wpdb->insert(
			$traffic,
			array(
				'created_at' => '2026-01-01 00:00:00',
				'ip'         => '198.51.100.7',
				'uri'        => '/ok',
				'referrer'   => '',
			)
		);
		$this->assertFalse( $this->table_exists( $wpdb->prefix . 'bouncer_counters' ) );

		Installer::maybe_upgrade();

		$this->assertSame( '3', get_option( Installer::DB_VERSION_OPTION ) );
		$this->assertArrayHasKey( 'user_id', $this->indexes_of( $wpdb->prefix . 'bouncer_traffic' ), 'dbDelta adds the new index to the old table' );
		$this->assertTrue( $this->table_exists( $wpdb->prefix . 'bouncer_counters' ) );
		$this->assertFalse( RedactionMigration::pending(), 'small tables finish within the upgrade request' );
		$this->assertFalse( wp_next_scheduled( RedactionMigration::HOOK ) );

		$uris = $wpdb->get_col( "SELECT uri FROM {$log} ORDER BY id" ); // phpcs:ignore WordPress.DB
		$this->assertSame( '/?key=[removed]&ok=1', $uris[0] );
		$this->assertSame( '/clean', $uris[1] );
		$reasons = $wpdb->get_col( "SELECT reason FROM {$log} ORDER BY id" ); // phpcs:ignore WordPress.DB
		$this->assertSame( '5 failed logins (last: unknown username) – locked out for 60 min', $reasons[2] );
		$this->assertStringContainsString( '"' . $login . '"', $reasons[3], 'an existing account stays' );
		$this->assertSame( 'Tried banned username "admin"', $reasons[4] );
		$t = $wpdb->get_results( "SELECT uri, referrer FROM {$traffic} ORDER BY id", ARRAY_A ); // phpcs:ignore WordPress.DB
		$this->assertSame( '/?token=[removed]', $t[0]['uri'] );
		$this->assertSame( 'https://example.org/?password=[removed]&a=1', $t[0]['referrer'] );
		$this->assertSame( '/ok', $t[1]['uri'] );
		$this->assertSame( '', $t[1]['referrer'] );
		wp_delete_user( $user_id );

		// A second run changes nothing.
		update_option( Installer::DB_VERSION_OPTION, '2' );
		Installer::maybe_upgrade();
		$this->assertSame( $uris, $wpdb->get_col( "SELECT uri FROM {$log} ORDER BY id" ) ); // phpcs:ignore WordPress.DB
	}

	public function test_upgrade_leaves_a_resumable_migration_for_cron_on_a_big_table(): void {
		global $wpdb;
		delete_option( RedactionMigration::STATE_OPTION );
		update_option( Installer::DB_VERSION_OPTION, '2' );
		$this->clear_cron();
		$log = $wpdb->prefix . 'bouncer_log';
		$n   = RedactionMigration::BATCH * 2 + 7;
		$sql = array();
		for ( $i = 0; $i < $n; $i++ ) {
			$sql[] = $wpdb->prepare( '(%s, %s, %s)', '2026-01-01 00:00:00', 'waf', "/p{$i}?token=S{$i}" );
		}
		$wpdb->query( "INSERT INTO {$log} (created_at, rule, uri) VALUES " . implode( ',', $sql ) ); // phpcs:ignore WordPress.DB

		$migration = new RedactionMigration( Installer::user_lookup() );
		RedactionMigration::begin();
		$this->assertFalse( $migration->run( 0.0 ), 'one batch, then stop' );
		$state = get_option( RedactionMigration::STATE_OPTION );
		$this->assertGreaterThan( 0, $state['log'] );
		$this->assertSame( (string) RedactionMigration::BATCH, (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$log} WHERE uri LIKE '%[removed]%'" ) ); // phpcs:ignore WordPress.DB
		RedactionMigration::schedule();
		$this->assertNotFalse( wp_next_scheduled( RedactionMigration::HOOK ) );

		$guard = 0;
		while ( ! $migration->run( 0.0 ) && ++$guard < 20 ) {
			$this->assertTrue( RedactionMigration::pending() );
		}
		$this->assertFalse( RedactionMigration::pending() );
		$this->assertSame( (string) $n, (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$log} WHERE uri LIKE '%[removed]%'" ) ); // phpcs:ignore WordPress.DB
		$this->assertSame( '0', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$log} WHERE uri LIKE '%token=S%'" ) ); // phpcs:ignore WordPress.DB
		$this->assertFalse( wp_next_scheduled( RedactionMigration::HOOK ) );
	}
}
