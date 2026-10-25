<?php
/**
 * Static checks on assets/columns.js (WPB-10b, SB-11).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Assets;

use PHPUnit\Framework\TestCase;

/**
 * @coversNothing
 */
final class ColumnsScriptTest extends TestCase {

	private const BANNED = array(
		'innerHTML',
		'outerHTML',
		'insertAdjacentHTML',
		'document.write',
		'eval(',
		'new Function',
		'cssText',
		"setAttribute('style'",
		'setAttribute("style"',
		'localStorage.clear',
		'jQuery',
		'createContextualFragment',
		'setHTMLUnsafe',
		'parseHTMLUnsafe',
		'DOMParser',
		'insertRule',
		'replaceSync',
	);

	/**
	 * Patterns for calls that are only dangerous with certain arguments.
	 */
	private const BANNED_PATTERNS = array(
		'a bare or constructed Function' => '/(?<![\w.])Function\s*\(/',
		'setAttribute of style'          => '/setAttribute\(\s*[\'"`]\s*style/i',
		'string-argument timers'         => '/set(?:Timeout|Interval)\(\s*[\'"`]/',
	);

	private function asset( string $name ): string {
		return (string) file_get_contents( dirname( __DIR__, 3 ) . '/wp-bouncer/assets/' . $name );
	}

	public function test_the_script_uses_no_html_or_code_injection_apis(): void {
		$js = $this->asset( 'columns.js' );
		$this->assertNotSame( '', $js );

		foreach ( self::BANNED as $needle ) {
			$this->assertStringNotContainsString( $needle, $js, "columns.js must not use $needle" );
		}
		foreach ( self::BANNED_PATTERNS as $what => $regex ) {
			$this->assertDoesNotMatchRegularExpression( $regex, $js, "columns.js must not use $what" );
		}
	}

	public function test_the_banned_patterns_catch_bad_samples(): void {
		$bad = array(
			'a bare or constructed Function' => array( 'Function("return 1")()', 'new Function ( "x" )' ),
			'setAttribute of style'          => array( "el.setAttribute('style', x)", 'el.setAttribute( "Style", x)', 'el.setAttribute(`style`, x)' ),
			'string-argument timers'         => array( "setTimeout('a()', 5)", 'setInterval( "a()", 5)' ),
		);
		foreach ( $bad as $what => $samples ) {
			foreach ( $samples as $sample ) {
				$this->assertMatchesRegularExpression( self::BANNED_PATTERNS[ $what ], $sample, $sample );
			}
		}
		$good = "el.setAttribute('aria-label', x); setTimeout(fn, 5); const f = function () {};";
		foreach ( self::BANNED_PATTERNS as $regex ) {
			$this->assertDoesNotMatchRegularExpression( $regex, $good );
		}
	}

	public function test_the_script_stays_small(): void {
		$this->assertLessThan( 7000, strlen( $this->asset( 'columns.js' ) ) );
	}

	public function test_only_columns_js_touches_the_width_storage_keys(): void {
		$this->assertStringNotContainsString( 'wpb_cols', $this->asset( 'admin.js' ) );
		$this->assertStringContainsString( 'wpb_cols:', $this->asset( 'columns.js' ) );
	}
}
