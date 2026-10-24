<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Log;

use PHPUnit\Framework\TestCase;
use WPBouncer\Admin\AdminController;
use WPBouncer\Log\BlockLog;

/**
 * Pure helpers on the log and export path. Database queries are covered by
 * the integration checklist in docs/testing.md.
 *
 * @covers \WPBouncer\Log\BlockLog::normalize
 * @covers \WPBouncer\Admin\AdminController::csv_safe
 */
final class BlockLogTest extends TestCase {

	public function test_normalize_fills_and_truncates(): void {
		$row = BlockLog::normalize(
			array(
				'ip'         => '203.0.113.1',
				'country'    => 'DEU',
				'uri'        => '/' . str_repeat( 'a', 5000 ),
				'user_agent' => "evil\x00\x1b[31m agent",
				'extra'      => 'ignored',
				'reason'     => array( 'not', 'scalar' ),
			)
		);
		$this->assertSame( array( 'ip', 'country', 'rule', 'action', 'reason', 'method', 'uri', 'user_agent' ), array_keys( $row ) );
		$this->assertSame( 'DE', $row['country'] );
		$this->assertSame( 2048, strlen( $row['uri'] ) );
		$this->assertSame( 'evil[31m agent', $row['user_agent'], 'control characters are stripped' );
		$this->assertSame( '', $row['reason'] );
		$this->assertSame( 'blocked', $row['action'], 'default action' );
	}

	/** @dataProvider csv_cells */
	public function test_csv_safe_neutralises_formulas( string $in, string $out ): void {
		$this->assertSame( $out, AdminController::csv_safe( $in ) );
	}

	public static function csv_cells(): array {
		return array(
			array( '=HYPERLINK("http://evil")', "'=HYPERLINK(\"http://evil\")" ),
			array( '+1', "'+1" ),
			array( '-1', '-1' ),
			array( '-x', "'-x" ),
			array( '@SUM(A1)', "'@SUM(A1)" ),
			array( '/wp-login.php', '/wp-login.php' ),
			array( '', '' ),
		);
	}
}
