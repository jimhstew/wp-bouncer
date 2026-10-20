<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use WPBouncer\Tests\Support\MemoryStore;
use WPBouncer\Tests\Support\FrozenClock;

/**
 * @covers \WPBouncer\Tests\Support\MemoryStore
 */
final class MemoryStoreTest extends TestCase {

	public function test_set_get_and_expiry(): void {
		$clock = new FrozenClock();
		$store = new MemoryStore( $clock );

		$store->set( 'k', 'v', 10 );
		$this->assertSame( 'v', $store->get( 'k' ) );

		$clock->advance( 9 );
		$this->assertSame( 'v', $store->get( 'k' ) );

		$clock->advance( 1 );
		$this->assertNull( $store->get( 'k' ) );
	}

	public function test_increment_uses_fixed_window(): void {
		$clock = new FrozenClock();
		$store = new MemoryStore( $clock );

		$this->assertSame( 1, $store->increment( 'c', 60 ) );
		$clock->advance( 30 );
		$this->assertSame( 2, $store->increment( 'c', 60 ) );
		$clock->advance( 29 );
		$this->assertSame( 3, $store->increment( 'c', 60 ) );

		// Window started at t=0; later increments must not extend it.
		$clock->advance( 1 );
		$this->assertSame( 1, $store->increment( 'c', 60 ) );
	}

	public function test_delete(): void {
		$store = new MemoryStore( new FrozenClock() );
		$store->set( 'k', 1, 10 );
		$store->delete( 'k' );
		$this->assertNull( $store->get( 'k' ) );
	}
}
