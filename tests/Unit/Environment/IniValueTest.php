<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Environment;

use PHPUnit\Framework\TestCase;
use WPBouncer\Environment\IniValue;

/**
 * @covers \WPBouncer\Environment\IniValue
 */
final class IniValueTest extends TestCase {

	/**
	 * @dataProvider flags
	 * @param string|false $raw Raw value.
	 */
	public function test_flag( $raw, ?bool $expected ): void {
		$this->assertSame( $expected, IniValue::flag( $raw ) );
	}

	/** @return array<string, array{string|false, ?bool}> */
	public static function flags(): array {
		return array(
			'On'       => array( 'On', true ),
			'on lower' => array( 'on', true ),
			'1'        => array( '1', true ),
			'true'     => array( 'true', true ),
			'yes'      => array( 'yes', true ),
			'stdout'   => array( 'stdout', null ),
			'stderr'   => array( 'stderr', null ),
			'Off'      => array( 'Off', false ),
			'0'        => array( '0', false ),
			'empty'    => array( '', false ),
			'no'       => array( 'no', false ),
			'-1'       => array( '-1', true ),
			'2'        => array( '2', true ),
			'unknown'  => array( 'sometimes', null ),
			'no ini'   => array( false, null ),
		);
	}

	public function test_stdout_and_stderr_are_values_of_display_errors_only(): void {
		$this->assertTrue( IniValue::flag( 'stdout', 'display_errors' ) );
		$this->assertTrue( IniValue::flag( 'stderr', 'display_errors' ) );
		$this->assertNull( IniValue::flag( 'stdout', 'log_errors' ) );
	}

	public function test_zend_assertions_is_a_number_where_minus_one_and_zero_are_off(): void {
		$this->assertFalse( IniValue::flag( '-1', 'zend.assertions' ) );
		$this->assertFalse( IniValue::flag( '0', 'zend.assertions' ) );
		$this->assertTrue( IniValue::flag( '1', 'zend.assertions' ) );
		$this->assertTrue( IniValue::flag( '-1', 'display_errors' ), 'any non-zero number is true for PHP flags' );
	}

	public function test_bytes(): void {
		$this->assertSame( 64 * 1048576, IniValue::bytes( '64M' ) );
		$this->assertSame( 2048, IniValue::bytes( '2k' ) );
		$this->assertSame( 1073741824, IniValue::bytes( '1G' ) );
		$this->assertSame( 500, IniValue::bytes( '500' ) );
		$this->assertSame( -1, IniValue::bytes( '-1' ) );
		$this->assertNull( IniValue::bytes( 'lots' ) );
		$this->assertNull( IniValue::bytes( false ) );
	}

	public function test_int(): void {
		$this->assertSame( 1000, IniValue::int( '1000' ) );
		$this->assertNull( IniValue::int( '1k' ) );
		$this->assertNull( IniValue::int( false ) );
	}
}
