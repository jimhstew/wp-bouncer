<?php
/**
 * WPB-12 on multisite: drift on one site leaves the other sites' records and logs alone.
 *
 * Runs only with WP_MULTISITE=1.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Audit;

use WPBouncer\Admin\AdminController;
use WPBouncer\Audit\FingerprintStore;
use WPBouncer\Audit\SettingsDriftMonitor;
use WPBouncer\Installer;
use WPBouncer\Log\BlockLog;
use WPBouncer\Settings;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Audit\SettingsDriftMonitor
 * @covers \WPBouncer\Audit\FingerprintStore
 */
final class MultisiteDriftTest extends IntegrationTestCase {

	/** @var int Second site. */
	private $site2 = 0;

	/** Set up two sites, each with a baseline. */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		$this->use_real_ddl();
		$this->fake_request();
		wp_set_current_user( 0 );
		$this->site2 = self::factory()->blog->create();
		foreach ( array( 1, $this->site2 ) as $id ) {
			switch_to_blog( $id );
			Installer::activate();
			update_option( Settings::OPTION, Settings::defaults() );
			delete_option( FingerprintStore::RECORD_OPTION );
			delete_option( FingerprintStore::MARKER_OPTION );
			delete_transient( FingerprintStore::THROTTLE_TRANSIENT );
			$this->plugin->drift_monitor()->check( SettingsDriftMonitor::TRIGGER_CRON );
			restore_current_blog();
		}
	}

	/**
	 * Number of settings rows in one site's log.
	 *
	 * @param int $blog Site id.
	 */
	private function rows_in( int $blog ): int {
		global $wpdb;
		switch_to_blog( $blog );
		$rows = (array) ( new BlockLog( $wpdb ) )->query( array( 'rule' => AdminController::SETTINGS_LOG_RULE ) );
		restore_current_blog();
		return count( $rows );
	}

	/**
	 * The stored fingerprint record of one site.
	 *
	 * @param int $blog Site id.
	 */
	private function record_of( int $blog ): string {
		switch_to_blog( $blog );
		$record = (string) get_option( FingerprintStore::RECORD_OPTION );
		restore_current_blog();
		return $record;
	}

	public function test_drift_on_site_two_leaves_site_one_alone(): void {
		global $wpdb;
		$this->assertNotSame( '', $this->record_of( 1 ) );
		$this->assertNotSame( '', $this->record_of( $this->site2 ) );
		$before_one = $this->record_of( 1 );

		switch_to_blog( $this->site2 );
		$new = array_replace_recursive( Settings::defaults(), array( 'mode' => 'monitor' ) );
		$wpdb->update( $wpdb->options, array( 'option_value' => serialize( $new ) ), array( 'option_name' => Settings::OPTION ) ); // phpcs:ignore WordPress.DB, WordPress.PHP.DiscouragedPHPFunctions
		wp_cache_delete( 'alloptions', 'options' );
		wp_cache_delete( Settings::OPTION, 'options' );
		$before_two = $this->record_of( $this->site2 );
		$this->plugin->drift_monitor()->check( SettingsDriftMonitor::TRIGGER_CRON );
		restore_current_blog();

		$this->assertSame( 1, $this->rows_in( $this->site2 ), 'the row is in the drifted site log' );
		$this->assertSame( 0, $this->rows_in( 1 ), 'site 1 log is untouched' );
		$this->assertNotSame( $before_two, $this->record_of( $this->site2 ), 'site 2 has a new baseline' );
		$this->assertSame( $before_one, $this->record_of( 1 ), 'site 1 record is unchanged' );

		// Site 1 still matches its own record: its check writes nothing.
		delete_transient( FingerprintStore::THROTTLE_TRANSIENT );
		$this->plugin->drift_monitor()->check( SettingsDriftMonitor::TRIGGER_CRON );
		$this->assertSame( 0, $this->rows_in( 1 ) );
		$this->assertSame( 1, $this->rows_in( $this->site2 ) );
	}
}
