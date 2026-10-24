<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Admin;

use PHPUnit\Framework\TestCase;

/**
 * admin.js reads its texts from wpBouncer.i18n; a key the PHP side forgets shows up as "undefined" on screen.
 *
 * @coversNothing
 */
final class AdminScriptStringsTest extends TestCase {

	public function test_every_i18n_key_the_script_reads_is_localized_by_the_controller(): void {
		$root = dirname( __DIR__, 3 ) . '/wp-bouncer';
		$js   = (string) file_get_contents( $root . '/assets/admin.js' );
		$php  = (string) file_get_contents( $root . '/src/Admin/AdminController.php' );

		preg_match_all( '/\bi18n\.(\w+)/', $js, $used );
		$this->assertNotEmpty( $used[1] );
		$this->assertSame( 1, preg_match( "/'i18n'\\s*=>\\s*array\\((.*?)\\n\\t{4}\\),/s", $php, $block ), 'the localized i18n array was not found' );
		preg_match_all( "/^\\s*'(\\w+)'\\s*=>/m", $block[1], $given );

		foreach ( array_unique( $used[1] ) as $key ) {
			$this->assertContains( $key, $given[1], "admin.js uses i18n.$key but AdminController does not localize it" );
		}
	}
}
