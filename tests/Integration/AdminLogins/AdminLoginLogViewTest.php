<?php
/**
 * Login rows in the Activity Log: filter, label, and the threat counts they must not change (AC 5, 6).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\AdminLogins;

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\LogListTable;
use WPBouncer\Log\BlockLog;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Admin\LogListTable
 * @covers \WPBouncer\Admin\AdminController::action_label
 * @covers \WPBouncer\Log\BlockLog::top
 * @covers \WPBouncer\Log\BlockLog::per_day
 */
final class AdminLoginLogViewTest extends IntegrationTestCase {

	private function log(): BlockLog {
		return new BlockLog( $GLOBALS['wpdb'] );
	}

	private function seed(): void {
		$log = $this->log();
		$log->record( array( 'ip' => '203.0.113.1', 'country' => 'DE', 'rule' => 'waf', 'action' => 'blocked', 'reason' => 'x' ) );
		$log->record( array( 'ip' => '203.0.113.1', 'country' => 'DE', 'rule' => 'waf', 'action' => 'blocked', 'reason' => 'x' ) );
		for ( $i = 0; $i < 5; $i++ ) {
			$log->record( array( 'ip' => '198.51.100.7', 'country' => 'FR', 'rule' => 'admin_login', 'action' => 'login', 'reason' => 'User ID 1: a — interactive password' ) );
		}
		$log->record( array( 'ip' => '198.51.100.7', 'country' => 'FR', 'rule' => 'alerts', 'action' => 'alert', 'reason' => 'x' ) );
	}

	public function test_top_and_per_day_do_not_count_login_rows(): void {
		$this->seed();
		$since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$this->assertSame( array( '203.0.113.1' => 2 ), $this->log()->top( 'ip', $since ) );
		$this->assertSame( array( 'DE' => 2 ), $this->log()->top( 'country', $since ) );
		$this->assertSame( array( 'waf' => 2 ), $this->log()->top( 'rule', $since ) );
		$this->assertSame( array( 'blocked' => 2 ), $this->log()->top( 'action', $since ) );
		$this->assertSame( array(), $this->log()->top( 'ip', $since, 10, 'login' ), 'a non-threat action stays excluded even when named, as alert always did' );
		$this->assertSame( 2, array_sum( $this->log()->per_day( 3 ) ) );
	}

	public function test_the_login_filter_selects_login_rows_alone(): void {
		$this->seed();
		$rows = $this->log()->query( array( 'action' => 'login' ) );
		$this->assertCount( 5, $rows );
		$this->assertSame( 5, $this->log()->count( array( 'action' => 'login' ) ) );
		$this->assertSame( 5, $this->log()->count( array( 'rule' => 'admin_login' ) ) );
		$this->assertSame( 8, $this->log()->count() );
	}

	public function test_the_dashboard_widget_numbers_ignore_login_rows(): void {
		$this->seed();
		$since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$p     = $this->log()->period_counts( gmdate( 'Y-m-d H:i:s', time() - 14 * DAY_IN_SECONDS ), gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS ), $since, gmdate( 'Y-m-d H:i:s', time() - 2 * DAY_IN_SECONDS ) );
		$this->assertArrayNotHasKey( 'login', $p );
		$this->assertSame( 2, array_sum( array_column( $p, 'd14' ) ), 'only the two blocked rows' );
		$recent = $this->log()->recent( 50, array( 'blocked', 'monitored', 'lockout', 'suppressed' ), $since );
		$this->assertCount( 2, $recent );
		foreach ( $recent as $r ) {
			$this->assertNotSame( 'login', $r['action'] );
		}
	}

	public function test_the_action_label_is_translated_and_is_text_not_colour(): void {
		$this->assertSame( 'Admin login', AdminController::action_label( BlockLogInterface::ACTION_LOGIN ) );
		$translate = static function ( $translation, $text, $domain ) {
			return 'wp-bouncer' === $domain && 'Admin login' === $text ? 'Administratoranmeldung' : $translation;
		};
		add_filter( 'gettext', $translate, 10, 3 );
		$this->assertSame( 'Administratoranmeldung', AdminController::action_label( BlockLogInterface::ACTION_LOGIN ) );

		$table = new LogListTable( $this->log() );
		$cell  = ( new \ReflectionMethod( $table, 'column_action' ) )->invoke( $table, array( 'action' => 'login' ) );
		remove_filter( 'gettext', $translate, 10 );
		$this->assertStringContainsString( '>Administratoranmeldung</span>', $cell, 'the badge carries text' );
		$this->assertStringContainsString( 'wpb-badge-login', $cell );
	}

	public function test_the_login_method_is_translated_on_display_but_stored_in_english(): void {
		$translate = static function ( $translation, $text, $domain ) {
			return 'wp-bouncer' === $domain && 'interactive password + two-factor' === $text ? 'Passwort + Zweitfaktor' : $translation;
		};
		add_filter( 'gettext', $translate, 10, 3 );
		$table = new LogListTable( $this->log() );
		$col   = new \ReflectionMethod( $table, 'column_reason' );
		$row   = array(
			'rule'   => 'admin_login',
			'action' => 'login',
			'reason' => 'User ID 3: jim — interactive password + two-factor — new location: IP range 203.0.113.0/24',
		);
		$cell  = $col->invoke( $table, $row );
		$plain = $col->invoke( $table, array( 'reason' => '<b>x</b> — interactive password' ) + $row );
		remove_filter( 'gettext', $translate, 10 );
		$this->assertSame( 'User ID 3: jim — Passwort + Zweitfaktor — new location: IP range 203.0.113.0/24', $cell );
		$this->assertStringNotContainsString( '<b>', $plain, 'the reason is escaped' );
		$this->assertSame( 'User ID 3: jim — interactive password + two-factor — new location: IP range 203.0.113.0/24', $row['reason'] );
		$other = $col->invoke( $table, array( 'rule' => 'waf', 'action' => 'blocked', 'reason' => 'x — interactive password' ) );
		$this->assertSame( 'x — interactive password', $other, 'other rows are not touched' );
	}

	public function test_the_label_is_escaped(): void {
		$evil = static function ( $translation, $text, $domain ) {
			return 'wp-bouncer' === $domain && 'Admin login' === $text ? '<img src=x onerror=alert(1)>' : $translation;
		};
		add_filter( 'gettext', $evil, 10, 3 );
		$table = new LogListTable( $this->log() );
		$cell  = ( new \ReflectionMethod( $table, 'column_action' ) )->invoke( $table, array( 'action' => 'login' ) );
		remove_filter( 'gettext', $evil, 10 );
		$this->assertStringNotContainsString( '<img', $cell );
	}

	public function test_the_filter_dropdown_and_rule_list_offer_logins(): void {
		$this->assertArrayHasKey( 'admin_login', AdminController::log_rule_labels() );
		$this->assertSame( 'Admin logins', AdminController::log_rule_labels()['admin_login'] );
		$table = new LogListTable( $this->log() );
		ob_start();
		( new \ReflectionMethod( $table, 'extra_tablenav' ) )->invoke( $table, 'top' );
		$html = (string) ob_get_clean();
		$this->assertMatchesRegularExpression( '/<option value="login"[^>]*>Admin login<\/option>/', $html );
		$this->assertMatchesRegularExpression( '/<option value="admin_login"[^>]*>Admin logins<\/option>/', $html );
	}

	public function test_the_login_badge_has_a_neutral_style_that_survives_forced_colors(): void {
		$css = (string) file_get_contents( dirname( __DIR__, 3 ) . '/wp-bouncer/assets/admin.css' );
		$this->assertMatchesRegularExpression( '/\.wpb-badge-login\s*\{/', $css );
		$this->assertMatchesRegularExpression( '/forced-colors[\s\S]*\.wpb-badge/', $css );
	}
}
