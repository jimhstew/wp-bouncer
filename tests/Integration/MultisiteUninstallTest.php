<?php
/**
 * Network uninstall and deactivation across three sites.
 *
 * Runs only with WP_MULTISITE=1.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration;

use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Installer;
use WPBouncer\Log\BlockLog;
use WPBouncer\Settings;

/**
 * @covers \WPBouncer\Installer
 * @covers \WPBouncer\Hardening\UploadsGuard
 */
final class MultisiteUninstallTest extends IntegrationTestCase {

	/** @var int[] Site ids: the main site and two more. */
	private $sites = array();

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		$this->use_real_ddl();
		// Give every site its own uploads folder (the helper's filter points all of them at one).
		add_filter(
			'upload_dir',
			function ( $dirs ) {
				$dirs['basedir'] = $this->uploads_dir . '/site' . get_current_blog_id();
				wp_mkdir_p( $dirs['basedir'] );
				return $dirs;
			},
			20
		);
		$this->sites = array( 1, self::factory()->blog->create(), self::factory()->blog->create() );
		foreach ( $this->sites as $id ) {
			switch_to_blog( $id );
			Installer::activate();
			update_option( Settings::OPTION, Settings::defaults() );
			update_option( 'wp_bouncer_last_purge', time() );
			update_option( 'wp_bouncer_migration_3', array( 'log' => 1 ) );
			update_option( 'wp_bouncer_counter_failed', 1 );
			update_option( UploadsGuard::STATE_OPTION, array( 'ok' => true ) );
			set_transient( 'wpb_' . md5( 'something' ), 1, 600 );
			set_transient( 'wpb_map_' . str_repeat( 'b', 20 ), array( 'v' => 1 ), 600 );
			set_transient( 'wpb_map_lock', 1, 600 );
			update_option( 'wpb_map_keys', array( 'gen' => 1, 'keys' => array() ), false );
			update_option( 'wpb_map_gen', 1, false );
			update_option( 'wp_bouncer_fp', '{}', false );
			update_option( 'wp_bouncer_fp_since', time(), false );
			set_transient( 'wp_bouncer_fp_check', 1, 600 );
			global $wpdb;
			( new BlockLog( $wpdb ) )->record( array( 'ip' => '198.51.100.1' ) );
			UploadsGuard::write_block();
			wp_schedule_single_event( time() + 60, UploadsGuard::CHECK_HOOK );
			restore_current_blog();
		}
		global $wpdb;
		$wpdb->query( 'COMMIT' );
	}

	private function uninstall(): void {
		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', plugin_basename( WP_BOUNCER_FILE ) );
		}
		$run = static function (): void {
			global $wpdb;
			include WP_BOUNCER_DIR . '/uninstall.php';
		};
		$this->without_settings_audit( $run );
	}

	private function super_admin(): void {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		grant_super_admin( $id );
		wp_set_current_user( $id );
	}

	/** Is our block in a site's uploads/.htaccess? */
	private function block_on( int $site ): bool {
		switch_to_blog( $site );
		$present = UploadsGuard::block_present();
		restore_current_blog();
		return $present;
	}

	public function test_a_network_uninstall_cleans_every_site(): void {
		global $wpdb;
		$this->super_admin();
		foreach ( $this->sites as $id ) {
			$this->assertTrue( $this->block_on( $id ), "site $id has the block before" );
		}

		$mark = 'wpb_' . md5( 'login|1' );
		set_site_transient( $mark, 1, HOUR_IN_SECONDS );
		set_site_transient( 'unrelated_keep', 1, HOUR_IN_SECONDS );

		$this->uninstall();

		$this->assertFalse( get_site_transient( $mark ), 'login dedupe site transient' );
		$this->assertSame( '0', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->sitemeta} WHERE meta_key LIKE '\\_site\\_transient\\_%wpb\\_%'" ), 'sitemeta rows' ); // phpcs:ignore WordPress.DB
		$this->assertNotFalse( get_site_transient( 'unrelated_keep' ) );

		foreach ( $this->sites as $id ) {
			switch_to_blog( $id );
			foreach ( array( 'bouncer_log', 'bouncer_geo', 'bouncer_traffic', 'bouncer_counters' ) as $t ) {
				$this->assertFalse( $this->table_exists( $wpdb->prefix . $t ), "site $id table $t" );
			}
			foreach ( array( Settings::OPTION, Installer::DB_VERSION_OPTION, 'wp_bouncer_last_purge', 'wp_bouncer_migration_3', 'wp_bouncer_counter_failed', UploadsGuard::STATE_OPTION, 'wpb_map_keys', 'wpb_map_gen', 'wp_bouncer_fp', 'wp_bouncer_fp_since' ) as $option ) {
				$this->assertFalse( get_option( $option ), "site $id option $option" );
			}
			$this->assertSame( '0', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_wpb\\_%'" ), "site $id transients: " . implode( ',', (array) $wpdb->get_col( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_%wpb\\_%'" ) ) ); // phpcs:ignore WordPress.DB
			$this->assertFalse( get_transient( 'wp_bouncer_fp_check' ), "site $id drift throttle" );
			$this->assertFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ), "site $id cron" );
			restore_current_blog();
			$this->assertFalse( $this->block_on( $id ), "site $id block" );
		}
	}

	public function test_uninstall_removes_the_main_site_block_whoever_runs_it(): void {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $id );
		$this->assertFalse( current_user_can( 'wpb_manage_firewall' ) );

		$this->uninstall();

		foreach ( $this->sites as $site ) {
			$this->assertFalse( $this->block_on( $site ), "site $site" );
		}
	}

	public function test_uninstall_with_no_user_and_no_wp_cli_still_removes_every_block(): void {
		wp_set_current_user( 0 );
		$this->assertFalse( defined( 'WP_CLI' ) && WP_CLI );

		$this->uninstall();

		foreach ( $this->sites as $site ) {
			$this->assertFalse( $this->block_on( $site ), "site $site" );
		}
	}

	public function test_deactivation_with_no_user_keeps_the_main_site_block(): void {
		wp_set_current_user( 0 );

		Installer::deactivate( false );

		$this->assertTrue( $this->block_on( 1 ) );
	}

	public function test_the_loop_visits_more_sites_than_one_page(): void {
		$seen = array();
		$ids  = array();
		for ( $i = 0; $i < 3; $i++ ) {
			$ids[] = self::factory()->blog->create();
		}
		Installer::for_each_site(
			static function () use ( &$seen ): void {
				$seen[] = get_current_blog_id();
			}
		);
		$this->assertSame( array(), array_diff( array_merge( $this->sites, $ids ), $seen ) );
		$this->assertSame( count( $seen ), count( array_unique( $seen ) ), 'each site once' );
		$this->assertSame( 1, get_current_blog_id(), 'back on the original site' );
	}

	public function test_network_wide_deactivation_clears_every_site(): void {
		$this->super_admin();
		foreach ( $this->sites as $id ) {
			switch_to_blog( $id );
			wp_schedule_event( time() + 60, 'daily', Installer::CRON_HOOK );
			restore_current_blog();
		}

		Installer::deactivate( true );

		foreach ( $this->sites as $id ) {
			switch_to_blog( $id );
			$this->assertFalse( wp_next_scheduled( Installer::CRON_HOOK ), "site $id daily cron" );
			$this->assertFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ), "site $id check cron" );
			restore_current_blog();
			$this->assertFalse( $this->block_on( $id ), "site $id block" );
		}
	}

	public function test_deactivating_on_the_main_site_as_a_site_admin_keeps_the_block(): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		Installer::deactivate( false );

		$this->assertTrue( $this->block_on( 1 ) );
		$this->assertFalse( wp_next_scheduled( UploadsGuard::CHECK_HOOK ), 'the cron events still go' );
	}

	public function test_deactivating_a_sub_site_as_its_admin_removes_that_sites_block(): void {
		switch_to_blog( $this->sites[1] );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		Installer::deactivate( false );
		restore_current_blog();

		$this->assertFalse( $this->block_on( $this->sites[1] ) );
		$this->assertTrue( $this->block_on( 1 ) );
	}
}
