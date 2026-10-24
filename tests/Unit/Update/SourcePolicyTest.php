<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Update;

use PHPUnit\Framework\TestCase;
use WPBouncer\Update\SourcePolicy;

/**
 * @covers \WPBouncer\Update\SourcePolicy
 */
final class SourcePolicyTest extends TestCase {

	public function test_filters_need_the_constant_defined_and_true(): void {
		$this->assertFalse( SourcePolicy::filters_allowed( false ) );
		$this->assertFalse( SourcePolicy::filters_allowed( false, true ) );
		$this->assertFalse( SourcePolicy::filters_allowed( true, false ) );
		$this->assertFalse( SourcePolicy::filters_allowed( true, null ) );
		$this->assertFalse( SourcePolicy::filters_allowed( true, 'false' ), 'a string is not true' );
		$this->assertFalse( SourcePolicy::filters_allowed( true, 1 ) );
		$this->assertTrue( SourcePolicy::filters_allowed( true, true ) );
	}
}
