<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use WPBouncer\Support\CsvSanitizer;

/**
 * @covers \WPBouncer\Support\CsvSanitizer
 */
final class CsvSanitizerTest extends TestCase {

	/** @dataProvider cells */
	public function test_cell( string $in, string $out ): void {
		$this->assertSame( $out, CsvSanitizer::cell( $in ) );
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function cells(): array {
		return array(
			'equals'                => array( '=1+1', "'=1+1" ),
			'plus formula'          => array( '+cmd|x', "'+cmd|x" ),
			'at'                    => array( '@SUM(A1)', "'@SUM(A1)" ),
			'leading space trigger' => array( ' =1+1', "' =1+1" ),
			'leading tab'           => array( "\tfoo", "'\tfoo" ),
			'leading cr'            => array( "\rfoo", "'\rfoo" ),
			'newline then trigger'  => array( "\n=1+1", "'\n'=1+1" ),
			'nbsp then trigger'     => array( "\xC2\xA0=1", "'\xC2\xA0=1" ),
			'full-width equals'     => array( "\xEF\xBC\x9D1+1", "'\xEF\xBC\x9D1+1" ),
			'full-width at'         => array( "\xEF\xBC\xA0SUM(1)", "'\xEF\xBC\xA0SUM(1)" ),
			'pipe'                  => array( '|calc', "'|calc" ),
			'percent'               => array( '%PATH%', "'%PATH%" ),
			'embedded semicolon'    => array( 'a;=1+1', "a;'=1+1" ),
			'comma space'           => array( 'a, @b', 'a, @b' ),
			'encoded comma'         => array( 'a,%20b', 'a,%20b' ),
			'ids list'              => array( '/?ids=1,-2', '/?ids=1,-2' ),
			'quote and newline'     => array( "x\"\n=1", "x\"\n'=1" ),
			'number then newline'   => array( "-5\n", "'-5\n" ),
			'embedded newline'      => array( "a\n+1", "a\n'+1" ),
			'negative number'       => array( '-5', '-5' ),
			'decimal'               => array( '3.25', '3.25' ),
			'minus x'               => array( '-x', "'-x" ),
			'plain path'            => array( '/wp-login.php?a=b', '/wp-login.php?a=b' ),
			'percent inside'        => array( '/a%20b', '/a%20b' ),
			'empty'                 => array( '', '' ),
			'invalid utf8'          => array( "ok\xFF;x", "ok\xFF;x" ),
		);
	}

	public function test_non_strings_are_cast(): void {
		$this->assertSame( '42', CsvSanitizer::cell( 42 ) );
		$this->assertSame( '', CsvSanitizer::cell( null ) );
	}
}
