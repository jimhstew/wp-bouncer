<?php
/**
 * uninstall.php removes the WPB-13 data and nothing else.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\AdminLogins;

use WPBouncer\AdminLogins\LoginHistoryRepository;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @coversNothing
 */
final class AdminLoginUninstallTest extends IntegrationTestCase {

	public function set_up() {
		parent::set_up();
		$this->use_real_ddl();
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

	private function count_options( array $names ): int {
		global $wpdb;
		$n = 0;
		foreach ( $names as $name ) {
			foreach ( array( '_transient_', '_transient_timeout_' ) as $prefix ) {
				$n += (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name = %s", $prefix . $name ) ); // phpcs:ignore WordPress.DB
			}
		}
		return $n;
	}

	public function test_uninstall_removes_login_histories_the_prune_cursor_and_login_transients(): void {
		global $wpdb;
		$key  = $wpdb->get_blog_prefix() . LoginHistoryRepository::META;
		$hist = array(
			'since' => time() - 100,
			'e'     => array( array( 'r' => '203.0.113.0/24', 'c' => 'DE', 't' => time() - 50 ) ),
		);
		$a    = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$b    = self::factory()->user->create( array( 'role' => 'administrator' ) );
		update_user_meta( $a, $key, $hist );
		update_user_meta( $b, $key, $hist );
		update_user_meta( $a, 'wpb_other_meta', 'keep' );
		update_user_meta( $a, $key . '_not', 'keep' );
		update_option( LoginHistoryRepository::CURSOR_OPTION, 42, false );

		$ours   = array( 'wpb_alert_count_login', 'wpb_alert_login_notice', 'wpb_alert_count', 'wpb_alert_settings_notice', 'wpb_' . md5( 'login_seen:1|203.0.113.0/24|application password (REST)' ), 'wpb_' . md5( 'login_alert:7' ) );
		$others = array( 'wpb_alert_count_loginx', 'wpb_alert_login_noticex', 'wpb_alert_count_other' );
		foreach ( array_merge( $ours, $others ) as $name ) {
			set_transient( $name, 'v', 600 );
		}
		$this->assertSame( 2 * count( $ours ), $this->count_options( $ours ), 'precondition' );

		$this->uninstall();

		$this->assertSame( '', get_user_meta( $a, $key, true ) );
		$this->assertSame( '', get_user_meta( $b, $key, true ) );
		$this->assertSame( 'keep', get_user_meta( $a, 'wpb_other_meta', true ), 'other meta stays' );
		$this->assertSame( 'keep', get_user_meta( $a, $key . '_not', true ) );
		$this->assertFalse( get_option( LoginHistoryRepository::CURSOR_OPTION ), 'cursor deleted' );
		$this->assertSame( 0, $this->count_options( $ours ), 'login transients deleted' );
		$this->assertSame( 2 * count( $others ), $this->count_options( $others ), 'look-alikes stay' );
		$this->assertSame( 0, (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s", $key ) ) ); // phpcs:ignore WordPress.DB
	}
}
