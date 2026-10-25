<?php
/**
 * Long Request / User-Agent / Referrer values stay inside the truncating wrapper (WPB-10a).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use ReflectionMethod;
use WPBouncer\Admin\LogListTable;
use WPBouncer\Admin\TrafficListTable;
use WPBouncer\Log\BlockLog;
use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Traffic\TrafficLog;

/**
 * @covers \WPBouncer\Admin\LogListTable
 * @covers \WPBouncer\Admin\TrafficListTable
 */
final class ListTableTruncationTest extends IntegrationTestCase {

	private const LONG = 'Mozilla/5.0 "x" <b>&amp;</b> ';

	/**
	 * @param object $table  List table.
	 * @param string $method Column method.
	 * @param array  $item   Row.
	 */
	private function cell( $table, string $method, array $item ): string {
		$m = new ReflectionMethod( $table, $method );
		return (string) $m->invoke( $table, $item );
	}

	private function assert_wrapped( string $html, string $full ): void {
		$this->assertMatchesRegularExpression( '/class="wpb-trunc[ "]/', $html );
		$this->assertStringContainsString( 'title="' . esc_attr( $full ) . '"', $html );
		$this->assertStringNotContainsString( '<b>', $html );
	}

	public function test_activity_log_cells_wrap_long_values(): void {
		$table = new LogListTable( new BlockLog( $GLOBALS['wpdb'] ) );
		$ua    = str_repeat( self::LONG, 20 );
		$uri   = '/?q=' . str_repeat( '"<a>', 80 );

		$this->assert_wrapped( $this->cell( $table, 'column_user_agent', array( 'user_agent' => $ua ) ), $ua );
		$this->assert_wrapped( $this->cell( $table, 'column_request', array( 'method' => 'GET', 'uri' => $uri ) ), $uri );
	}

	public function test_traffic_cells_wrap_long_values(): void {
		$table = new TrafficListTable( new TrafficLog( $GLOBALS['wpdb'] ) );
		$ua    = str_repeat( self::LONG, 20 );
		$uri   = '/?q=' . str_repeat( '"<a>', 80 );

		$this->assert_wrapped( $this->cell( $table, 'column_client', array( 'client' => 'browser', 'user_agent' => $ua ) ), $ua );
		$this->assert_wrapped( $this->cell( $table, 'column_request', array( 'method' => 'GET', 'uri' => $uri ) ), $uri );
		$this->assert_wrapped( $this->cell( $table, 'column_referrer', array( 'referrer' => $uri ) ), $uri );
	}

	public function test_truncation_css_is_relative_to_the_cell(): void {
		$css = (string) file_get_contents( dirname( __DIR__, 3 ) . '/wp-bouncer/assets/admin.css' );
		$this->assertSame( 1, preg_match( '/^\s*\.wpb-trunc\s*\{([^}]*)\}/m', $css, $m ), 'the .wpb-trunc rule exists' );
		$this->assertMatchesRegularExpression( '/max-width\s*:\s*100%/', $m[1], 'capped at the cell width' );
		$this->assertMatchesRegularExpression( '/display\s*:\s*block/', $m[1], 'a block, so the cap resolves against the cell' );
		$this->assertMatchesRegularExpression( '/text-overflow\s*:\s*ellipsis/', $m[1], 'long values end in an ellipsis' );
		$this->assertMatchesRegularExpression( '/td\.column-request[^{]*td\.column-user_agent[^{]*\{[^}]*overflow\s*:\s*hidden/', $css, 'backstop: the long-text cells clip' );
		$this->assertDoesNotMatchRegularExpression( '/\.wpb-trunc[^{]*\{[^}]*max-width:\s*\d+px/', $css, 'no fixed pixel cap' );
	}
}
