<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Storage;

use PHPUnit\Framework\TestCase;
use WPBouncer\Storage\ObjectCacheCounter;

require_once dirname( __DIR__, 2 ) . '/Support/object_cache_stubs.php';

/**
 * @covers \WPBouncer\Storage\ObjectCacheCounter
 */
final class ObjectCacheCounterTest extends TestCase {

	protected function setUp(): void {
		\WPBouncer\Storage\wpb_test_cache( array() );
	}

	public function test_counts_up_and_reads_back(): void {
		$c = new ObjectCacheCounter();
		$this->assertSame( 1, $c->add_or_increment( 'k', 60 ) );
		$this->assertSame( 2, $c->add_or_increment( 'k', 60 ) );
		$this->assertSame( 2, $c->get( 'k' ) );
		$this->assertSame( 1, $c->add_or_increment( 'other', 60 ) );
	}

	public function test_decrement_floors_at_zero(): void {
		$c = new ObjectCacheCounter();
		$c->add_or_increment( 'k', 60 );
		$c->decrement( 'k' );
		$c->decrement( 'k' );
		$this->assertSame( 0, $c->get( 'k' ) );
		$c->decrement( 'never-set' );
		$this->assertSame( 0, $c->get( 'never-set' ) );
	}

	public function test_delete_forgets(): void {
		$c = new ObjectCacheCounter();
		$c->add_or_increment( 'k', 60 );
		$c->delete( 'k' );
		$this->assertSame( 0, $c->get( 'k' ) );
		$this->assertSame( 1, $c->add_or_increment( 'k', 60 ) );
	}

	public function test_keys_are_hashed_in_the_plugin_group(): void {
		( new ObjectCacheCounter() )->add_or_increment( 'login_n:2001:db8::/64', 60 );
		$keys = array_keys( \WPBouncer\Storage\wpb_test_cache() );
		$this->assertCount( 1, $keys );
		$this->assertStringStartsWith( 'wp_bouncer:wpb_ctr_', $keys[0] );
		$this->assertStringNotContainsString( '2001', $keys[0] );
	}
}
