<?php
/**
 * A drift row has no IP and no country: it must render in the Activity Log without warnings (WPB-12).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\LogListTable;
use WPBouncer\Audit\DriftVerdict;
use WPBouncer\Log\BlockLog;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Admin\LogListTable
 * @covers \WPBouncer\Admin\AdminController::csv_safe
 */
final class DriftRowRenderTest extends IntegrationTestCase {

	/** @return array<string, string> A stored drift row, read back from the log. */
	private function drift_row(): array {
		global $wpdb;
		$log = new BlockLog( $wpdb );
		$log->record(
			array(
				'ip'     => '',
				'rule'   => AdminController::SETTINGS_LOG_RULE,
				'action' => 'alert',
				'reason' => DriftVerdict::HEADS[ DriftVerdict::CHANGED ] . ' (actor unknown): mode',
			)
		);
		$rows = $log->query( array( 'rule' => AdminController::SETTINGS_LOG_RULE ) );
		$this->assertNotEmpty( $rows );
		return $rows[0];
	}

	public function test_every_column_renders_for_a_row_without_ip_and_country(): void {
		$row = $this->drift_row();
		$this->assertSame( '', $row['ip'] );
		$this->assertSame( '', $row['country'] );

		$errors = array();
		set_error_handler( // phpcs:ignore WordPress.PHP.DevelopmentFunctions
			static function ( $no, $str ) use ( &$errors ) {
				$errors[] = $str;
				return true;
			}
		);
		try {
			$table = new LogListTable( new BlockLog( $GLOBALS['wpdb'] ) );
			$html  = array();
			foreach ( array( 'created_at', 'ip', 'country', 'rule', 'action', 'reason', 'request', 'user_agent' ) as $column ) {
				$m = new \ReflectionMethod( $table, 'column_' . $column );
				$html[ $column ] = (string) $m->invoke( $table, $row );
			}
			$cells = array_map( array( AdminController::class, 'csv_safe' ), array( $row['created_at'], $row['ip'], $row['country'], $row['rule'], $row['action'], $row['reason'], $row['method'], $row['uri'], $row['user_agent'] ) );
		} finally {
			restore_error_handler();
		}

		$this->assertSame( array(), $errors );
		$this->assertStringContainsString( 'Changed outside WP Bouncer', $html['reason'] );
		$this->assertStringContainsString( '—', $html['country'] );
		$this->assertSame( '', $html['request'] );
		$this->assertSame( '', $cells[1] );
		$this->assertSame( '', $cells[2] );
		$this->assertSame( 'settings', $cells[3] );
	}

	public function test_the_table_prepares_and_displays_with_a_drift_row(): void {
		$this->drift_row();
		set_current_screen( 'dashboard' );
		$table = new LogListTable( new BlockLog( $GLOBALS['wpdb'] ) );
		ob_start();
		$table->prepare_items();
		$table->display();
		$out = (string) ob_get_clean();
		$this->assertStringContainsString( 'Changed outside WP Bouncer', $out );
	}
}
