<?php
/**
 * Drag-to-resize columns on the Activity Log and Traffic tabs: enqueue rules and header markup (WPB-10b).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\ColumnResize;
use WPBouncer\Admin\LogListTable;
use WPBouncer\Admin\TrafficListTable;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Admin\ColumnResize
 * @covers \WPBouncer\Admin\LogListTable
 * @covers \WPBouncer\Admin\TrafficListTable
 * @covers \WPBouncer\Admin\AdminController::enqueue_assets
 */
final class ColumnResizeTest extends IntegrationTestCase {

	/** @var AdminController */
	private $admin;

	public function set_up() {
		parent::set_up();
		$this->admin = new AdminController( $this->plugin );
		$this->fake_request();
		$GLOBALS['hook_suffix'] = 'toplevel_page_wp-bouncer';
		set_current_screen( 'toplevel_page_wp-bouncer' );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
	}

	public function tear_down() {
		wp_dequeue_script( 'wp-bouncer-cols' );
		wp_deregister_script( 'wp-bouncer-cols' );
		wp_dequeue_script( 'wp-bouncer-admin' );
		wp_deregister_script( 'wp-bouncer-admin' );
		unset( $GLOBALS['current_screen'], $GLOBALS['hook_suffix'] );
		parent::tear_down();
	}

	private function enqueue( ?string $tab, string $hook = 'toplevel_page_wp-bouncer' ): void {
		unset( $_GET['tab'] );
		if ( null !== $tab ) {
			$_GET['tab'] = $tab;
		}
		$this->admin->enqueue_assets( $hook );
	}

	private function render( string $tab ): string {
		$_GET['tab'] = $tab;
		ob_start();
		$this->admin->render();
		return (string) ob_get_clean();
	}

	/** @return array<string, array{0: string}> */
	public static function resizable_tabs(): array {
		return array(
			'log'     => array( 'log' ),
			'traffic' => array( 'traffic' ),
		);
	}

	/** @return array<string, array{0: ?string}> */
	public static function other_tabs(): array {
		return array(
			'dashboard' => array( 'dashboard' ),
			'general'   => array( 'general' ),
			'rules'     => array( 'rules' ),
			'countries' => array( 'countries' ),
			'tools'     => array( 'tools' ),
			'missing'   => array( null ),
			'logx'      => array( 'logx' ),
		);
	}

	/**
	 * @dataProvider resizable_tabs
	 */
	public function test_the_script_is_enqueued_for_the_two_tables_only( string $tab ): void {
		$this->enqueue( $tab );

		$this->assertTrue( wp_script_is( 'wp-bouncer-cols', 'enqueued' ) );
		$data = (string) wp_scripts()->get_data( 'wp-bouncer-cols', 'data' );
		$this->assertStringContainsString( '"table":"' . $tab . '"', $data );
		$this->assertStringNotContainsString( 'nonce', strtolower( $data ) );
		$this->assertStringNotContainsString( 'geoNonce', $data );
		$this->assertStringContainsString( 'assets/columns.js', (string) wp_scripts()->registered['wp-bouncer-cols']->src );
	}

	/**
	 * @dataProvider other_tabs
	 */
	public function test_the_script_is_not_enqueued_elsewhere( ?string $tab ): void {
		$this->enqueue( $tab );

		$this->assertFalse( wp_script_is( 'wp-bouncer-cols', 'enqueued' ) );
		$this->assertTrue( wp_script_is( 'wp-bouncer-admin', 'enqueued' ), 'the 1.2.0 assets still load' );
	}

	public function test_a_crafted_tab_never_reaches_the_page_as_anything_but_a_slug_constant(): void {
		// sanitize_key() strips the slashes and dots, so this is the traffic tab. The localized value is our constant either way.
		$this->enqueue( 'Traffic/../' );

		$this->assertTrue( wp_script_is( 'wp-bouncer-cols', 'enqueued' ) );
		$this->assertStringContainsString( '"table":"traffic"', (string) wp_scripts()->get_data( 'wp-bouncer-cols', 'data' ) );
	}

	public function test_the_script_is_not_enqueued_on_other_screens(): void {
		$this->enqueue( 'log', 'index.php' );

		$this->assertFalse( wp_script_is( 'wp-bouncer-cols', 'enqueued' ) );
		$this->assertFalse( wp_script_is( 'wp-bouncer-admin', 'enqueued' ) );
	}

	public function test_the_existing_wpbouncer_data_is_unchanged(): void {
		$this->enqueue( 'log' );

		$data = (string) wp_scripts()->get_data( 'wp-bouncer-admin', 'data' );
		$this->assertSame( 1, preg_match( '/var wpBouncer = (\{.*\});/s', $data, $m ) );
		$cfg = json_decode( $m[1], true );
		$this->assertSame( array( 'yourIp', 'ajaxUrl', 'geoNonce', 'toolsUrl', 'i18n' ), array_keys( $cfg ) );
		$this->assertArrayNotHasKey( 'table', $cfg );
	}

	/**
	 * @dataProvider resizable_tabs
	 */
	public function test_header_cells_carry_the_resize_attributes( string $tab ): void {
		$html = $this->render( $tab );

		$table = 'log' === $tab ? new LogListTable( $this->plugin->log() ) : new TrafficListTable( $this->plugin->traffic_log() );
		$cols  = array_keys( $table->get_columns() );

		$this->assertSame( 1, preg_match( '#<thead>(.*?)</thead>#s', $html, $head ) );
		$this->assertSame( 1, preg_match( '#<tfoot>(.*?)</tfoot>#s', $html, $foot ) );
		$this->assertSame( count( $cols ), preg_match_all( '/<th\b[^>]*\sdata-wpb-col="([a-z_]+)"[^>]*>/', $head[1], $m ) );
		$this->assertSame( $cols, $m[1] );
		foreach ( $m[0] as $i => $tag ) {
			$this->assertStringContainsString( ' id=\'' . $m[1][ $i ] . '\'', $tag );
			$this->assertMatchesRegularExpression( '/ data-wpb-min="\d+"/', $tag );
			$this->assertMatchesRegularExpression( '/ data-wpb-label="[^"<>]+"/', $tag );
		}
		$this->assertStringNotContainsString( 'data-wpb-', $foot[1] );
		$this->assertStringContainsString( 'orderby=', $head[1], 'the sort links are intact' );
		$this->assertStringNotContainsString( 'wpb-col-handle', $html, 'handles are built by JS only' );
		$this->assertSame( 1, preg_match_all( '/<button type="button" class="button wpb-cols-reset" hidden>/', $html ) );
	}

	/**
	 * @dataProvider resizable_tabs
	 */
	public function test_the_header_markup_is_core_markup_plus_the_three_attributes( string $tab ): void {
		$_GET['tab'] = $tab;
		$table       = 'log' === $tab ? new LogListTable( $this->plugin->log() ) : new TrafficListTable( $this->plugin->traffic_log() );

		ob_start();
		$table->print_column_headers( true );
		$ours = (string) ob_get_clean();
		ob_start();
		( new \ReflectionMethod( \WP_List_Table::class, 'print_column_headers' ) )->invoke( $table, true );
		$core = (string) ob_get_clean();

		$this->assertNotSame( $core, $ours );
		$this->assertStringContainsString( 'orderby=', $core, 'the fixture has sortable headers' );
		$stripped = (string) preg_replace( '/ data-wpb-(?:col|min|label)="[^"]*"/', '', $ours );
		$this->assertSame( $core, $stripped );

		ob_start();
		$table->print_column_headers( false );
		$foot = (string) ob_get_clean();
		$this->assertStringNotContainsString( 'data-wpb-', $foot );
		$this->assertStringNotContainsString( ' id=', $foot, 'the footer row has no ids' );
	}

	public function test_annotate_escapes_a_hostile_column_id_and_label(): void {
		$id   = 'a"><script>x()</script>';
		$html = '<th id="' . esc_attr( $id ) . '">A</th>';

		$out = ColumnResize::annotate( $html, array( $id => 'L"><img src=x onerror=y()>' ), array( $id => -5 ) );

		$this->assertStringNotContainsString( '<script>', $out );
		$this->assertStringNotContainsString( '<img', $out );
		$this->assertStringContainsString( 'data-wpb-min="1"', $out, 'a non-positive minimum is raised to 1' );
	}

	public function test_the_narrow_columns_have_a_smaller_minimum(): void {
		$log = $this->render( 'log' );
		$this->assertMatchesRegularExpression( '/<th[^>]* data-wpb-col="country"[^>]* data-wpb-min="44"/', $log );
		$this->assertMatchesRegularExpression( '/<th[^>]* data-wpb-col="request"[^>]* data-wpb-min="60"/', $log );

		$traffic = $this->render( 'traffic' );
		$this->assertMatchesRegularExpression( '/<th[^>]* data-wpb-col="status"[^>]* data-wpb-min="44"/', $traffic );
	}

	public function test_the_truncating_wrappers_survive(): void {
		$this->plugin->log()->record(
			array(
				'ip'         => '198.51.100.23',
				'rule'       => 'waf',
				'reason'     => 'x',
				'uri'        => '/long',
				'user_agent' => 'UA',
			)
		);

		$this->assertStringContainsString( 'wpb-trunc', $this->render( 'log' ) );
	}

	public function test_annotate_leaves_unknown_cells_alone(): void {
		$html = '<tr><th id="a" class="x">A</th><th id="zzz">Z</th><td id="a">td</td></tr>';

		$out = ColumnResize::annotate( $html, array( 'a' => 'Alpha' ), array( 'a' => 44 ) );

		$this->assertStringContainsString( 'data-wpb-col="a"', $out );
		$this->assertStringContainsString( 'data-wpb-min="44"', $out );
		$this->assertSame( 1, substr_count( $out, 'data-wpb-col' ) );
		$this->assertStringContainsString( '<th id="zzz">Z</th>', $out );
		$this->assertStringContainsString( '<td id="a">td</td>', $out );
	}

	public function test_annotate_returns_the_input_when_nothing_matches(): void {
		$html = '<tr><th id="zzz">Z</th><th>plain</th></tr>';

		$this->assertSame( $html, ColumnResize::annotate( $html, array( 'a' => 'Alpha' ), array() ) );
		$this->assertSame( '', ColumnResize::annotate( '', array( 'a' => 'Alpha' ), array() ) );
	}

	public function test_annotate_uses_the_default_minimum_and_escapes_the_label(): void {
		$out = ColumnResize::annotate( '<th id="a">A</th>', array( 'a' => '<b>"x"</b> & <i>y' ), array() );

		$this->assertStringContainsString( 'data-wpb-min="' . ColumnResize::DEFAULT_MIN . '"', $out );
		$this->assertStringNotContainsString( '<b>', $out );
		$this->assertStringNotContainsString( '<i>', $out );
		$this->assertSame( 1, preg_match( '/data-wpb-label="([^"]*)"/', $out, $m ) );
		$this->assertSame( '"x" & y', html_entity_decode( $m[1], ENT_QUOTES ) );
		$this->assertStringNotContainsString( '& ', $m[1], 'the ampersand is escaped' );
	}
}
