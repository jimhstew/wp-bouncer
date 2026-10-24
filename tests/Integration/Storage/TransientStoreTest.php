<?php
/**
 * TransientStore on WordPress's transient API (wp_options, no object cache).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Storage;

use WPBouncer\Storage\TransientStore;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Storage\TransientStore
 */
final class TransientStoreTest extends IntegrationTestCase {

	/** @var TransientStore */
	private $store;

	public function set_up() {
		parent::set_up();
		$this->store = new TransientStore();
	}

	/** Option name of the transient behind a key. */
	private function transient_name( string $key ): string {
		return 'wpb_' . md5( $key );
	}

	/**
	 * Move a key's expiry (the value's own "e" field) into the past.
	 *
	 * @param string $key Logical key.
	 */
	private function expire_inner( string $key ): void {
		$name        = $this->transient_name( $key );
		$data        = get_transient( $name );
		$data['e']   = time() - 5;
		set_transient( $name, $data, HOUR_IN_SECONDS );
	}

	public function test_get_returns_null_for_unknown_keys(): void {
		$this->assertNull( $this->store->get( 'nope' ) );
	}

	public function test_set_then_get_round_trips_scalars_and_arrays(): void {
		$this->store->set( 'int', 5, 60 );
		$this->store->set( 'str', 'hello', 60 );
		$this->store->set( 'arr', array( 'a' => 1, 'b' => array( 2 ) ), 60 );
		$this->store->set( 'false', false, 60 );
		$this->store->set( 'zero', 0, 60 );

		$this->assertSame( 5, $this->store->get( 'int' ) );
		$this->assertSame( 'hello', $this->store->get( 'str' ) );
		$this->assertSame( array( 'a' => 1, 'b' => array( 2 ) ), $this->store->get( 'arr' ) );
		$this->assertFalse( $this->store->get( 'false' ), 'a stored false is not "missing"' );
		$this->assertSame( 0, $this->store->get( 'zero' ) );
	}

	public function test_keys_are_hashed_into_safe_transient_names(): void {
		$key = 'ban:' . str_repeat( 'x', 400 ) . ':üñí';
		$this->store->set( $key, 1, 60 );

		$this->assertSame( 1, $this->store->get( $key ) );
		$this->assertNotFalse( get_transient( $this->transient_name( $key ) ), 'stored under wpb_<md5>' );
		$this->assertLessThanOrEqual( 172, strlen( $this->transient_name( $key ) ) );
	}

	public function test_the_value_is_stored_in_wp_options_with_a_timeout(): void {
		$this->store->set( 'k', 1, 120 );
		$name = $this->transient_name( 'k' );

		$timeout = (int) get_option( '_transient_timeout_' . $name );

		$this->assertEqualsWithDelta( time() + 120, $timeout, 3 );
	}

	public function test_set_overwrites(): void {
		$this->store->set( 'k', 1, 60 );
		$this->store->set( 'k', 2, 60 );

		$this->assertSame( 2, $this->store->get( 'k' ) );
	}

	public function test_delete_removes_and_is_safe_on_unknown_keys(): void {
		$this->store->set( 'k', 1, 60 );

		$this->store->delete( 'k' );
		$this->store->delete( 'never-set' );

		$this->assertNull( $this->store->get( 'k' ) );
	}

	public function test_get_treats_an_elapsed_window_as_missing_even_if_the_row_lingers(): void {
		$this->store->set( 'k', 'v', 60 );
		$this->expire_inner( 'k' );

		$this->assertNull( $this->store->get( 'k' ) );
	}

	public function test_get_returns_null_when_the_transient_expired_in_wordpress(): void {
		$this->store->set( 'k', 'v', 60 );
		update_option( '_transient_timeout_' . $this->transient_name( 'k' ), time() - 10 );

		$this->assertNull( $this->store->get( 'k' ) );
	}

	public function test_get_ignores_foreign_values_under_our_name(): void {
		set_transient( $this->transient_name( 'k' ), 'not-our-format', 60 );

		$this->assertNull( $this->store->get( 'k' ) );
	}

	public function test_a_zero_or_negative_ttl_still_lasts_one_second(): void {
		$this->store->set( 'k', 'v', 0 );
		$this->store->set( 'k2', 'v', -50 );

		$this->assertSame( 'v', $this->store->get( 'k' ) );
		$this->assertSame( 'v', $this->store->get( 'k2' ) );
	}

	public function test_increment_starts_at_one_and_counts_up(): void {
		$this->assertSame( 1, $this->store->increment( 'c', 60 ) );
		$this->assertSame( 2, $this->store->increment( 'c', 60 ) );
		$this->assertSame( 3, $this->store->increment( 'c', 60 ) );
		$this->assertSame( 3, $this->store->get( 'c' ) );
	}

	public function test_counters_are_independent(): void {
		$this->store->increment( 'a', 60 );
		$this->store->increment( 'a', 60 );

		$this->assertSame( 1, $this->store->increment( 'b', 60 ) );
		$this->assertSame( 3, $this->store->increment( 'a', 60 ) );
	}

	public function test_increment_does_not_extend_the_window(): void {
		$this->store->increment( 'c', 100 );
		$name = $this->transient_name( 'c' );
		$data = get_transient( $name );
		// Pretend the window started 90 seconds ago.
		$data['e'] = time() + 10;
		set_transient( $name, $data, 10 );

		$this->store->increment( 'c', 100 );

		$timeout = (int) get_option( '_transient_timeout_' . $name );
		$this->assertLessThanOrEqual( time() + 11, $timeout, 'the original end of the window is kept' );
	}

	public function test_increment_restarts_after_the_window_ends(): void {
		$this->store->increment( 'c', 60 );
		$this->store->increment( 'c', 60 );
		$this->expire_inner( 'c' );

		$this->assertSame( 1, $this->store->increment( 'c', 60 ) );
		$this->assertSame( 1, $this->store->get( 'c' ) );
	}

	public function test_increment_after_delete_restarts(): void {
		$this->store->increment( 'c', 60 );
		$this->store->increment( 'c', 60 );
		$this->store->delete( 'c' );

		$this->assertSame( 1, $this->store->increment( 'c', 60 ) );
	}

	public function test_increment_over_a_set_value_continues_from_it(): void {
		$this->store->set( 'c', 10, 60 );

		$this->assertSame( 11, $this->store->increment( 'c', 60 ) );
	}
}
