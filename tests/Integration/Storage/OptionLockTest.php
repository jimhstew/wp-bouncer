<?php
/**
 * The option-row lock: one winner, a single takeover of a stale lock, owner-only release.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Storage;

use WPBouncer\Storage\OptionLock;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Storage\OptionLock
 */
final class OptionLockTest extends IntegrationTestCase {

	private const NAME = 'wp_bouncer_test_lock';

	/** Start with no lock row. */
	public function set_up() {
		parent::set_up();
		delete_option( self::NAME );
	}

	/**
	 * Put a lock row of a given age in place, as another request would have.
	 *
	 * @param int $age Seconds old.
	 */
	private function plant( int $age ): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", self::NAME, ( time() - $age ) . '|othertoken' ) ); // phpcs:ignore WordPress.DB
	}

	private function held(): bool {
		global $wpdb;
		return null !== $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::NAME ) ); // phpcs:ignore WordPress.DB
	}

	public function test_a_second_claim_fails_while_the_lock_is_held(): void {
		$lock = new OptionLock( self::NAME, 60 );
		$a    = $lock->claim();
		$this->assertNotNull( $a );
		$this->assertNull( $lock->claim() );
		$this->assertNull( ( new OptionLock( self::NAME, 60 ) )->claim(), 'another instance is refused too' );
		$lock->release( $a );
		$this->assertFalse( $this->held() );
		$this->assertNotNull( $lock->claim(), 'free again after the release' );
	}

	public function test_a_stale_lock_is_taken_over_exactly_once(): void {
		$this->plant( 120 );
		$lock  = new OptionLock( self::NAME, 60 );
		$first = $lock->claim();
		$this->assertNotNull( $first, 'the stale lock is taken over' );
		$this->assertNull( $lock->claim(), 'the new lock is fresh, so a second claim fails' );
		$this->assertNull( ( new OptionLock( self::NAME, 60 ) )->claim() );
	}

	public function test_a_lock_dated_in_the_future_or_malformed_is_taken_over(): void {
		global $wpdb;
		foreach ( array( ( time() + DAY_IN_SECONDS ) . '|othertoken', 'garbage', time() . '|', '|abc' ) as $value ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", self::NAME ) ); // phpcs:ignore WordPress.DB
			$wpdb->query( $wpdb->prepare( "INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", self::NAME, $value ) ); // phpcs:ignore WordPress.DB
			$this->assertNotNull( ( new OptionLock( self::NAME, 60 ) )->claim(), $value );
		}
	}

	public function test_a_fresh_lock_is_not_taken_over(): void {
		$this->plant( 5 );
		$this->assertNull( ( new OptionLock( self::NAME, 60 ) )->claim() );
		$this->assertTrue( $this->held() );
	}

	public function test_a_wrong_token_release_leaves_the_lock(): void {
		$lock  = new OptionLock( self::NAME, 60 );
		$token = $lock->claim();
		$this->assertNotNull( $token );
		$lock->release( 'wrongtoken' );
		$lock->release( '' );
		$this->assertTrue( $this->held() );
		$this->assertNull( $lock->claim() );
		$lock->release( (string) $token );
		$this->assertFalse( $this->held() );
	}

	public function test_releasing_a_lock_that_is_not_held_is_harmless(): void {
		( new OptionLock( self::NAME, 60 ) )->release( 'whatever' );
		$this->assertFalse( $this->held() );
	}
}
