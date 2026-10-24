<?php
/**
 * TableCounter against the real database (MySQL, MariaDB).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Storage;

use WPBouncer\Storage\TableCounter;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Storage\TableCounter
 */
final class TableCounterTest extends IntegrationTestCase {

	private int $now = 1700000000;

	private TableCounter $counter;

	public function set_up() {
		parent::set_up();
		global $wpdb;
		$wpdb->query( "DELETE FROM {$wpdb->prefix}bouncer_counters" ); // phpcs:ignore WordPress.DB
		$this->counter = new TableCounter( fn (): int => $this->now );
	}

	public function test_counts_up_inside_the_window(): void {
		$this->assertSame( 1, $this->counter->add_or_increment( 'k', 60 ) );
		$this->assertSame( 2, $this->counter->add_or_increment( 'k', 60 ) );
		$this->assertSame( 3, $this->counter->add_or_increment( 'k', 60 ) );
		$this->assertSame( 3, $this->counter->get( 'k' ) );
		$this->assertSame( 1, $this->counter->add_or_increment( 'other', 60 ) );
	}

	public function test_the_window_is_not_extended(): void {
		$this->counter->add_or_increment( 'k', 60 );
		$this->now += 59;
		$this->assertSame( 2, $this->counter->add_or_increment( 'k', 60 ) );
		$this->now += 1;
		$this->assertSame( 1, $this->counter->add_or_increment( 'k', 60 ), 'a new window starts at the old one\'s end' );
		$this->assertSame( 1, $this->counter->get( 'k' ) );
	}

	public function test_get_ignores_an_ended_window(): void {
		$this->counter->add_or_increment( 'k', 60 );
		$this->now += 60;
		$this->assertSame( 0, $this->counter->get( 'k' ) );
	}

	public function test_decrement_never_goes_below_zero(): void {
		$this->counter->add_or_increment( 'k', 60 );
		$this->counter->add_or_increment( 'k', 60 );
		$this->counter->decrement( 'k' );
		$this->assertSame( 1, $this->counter->get( 'k' ) );
		$this->counter->decrement( 'k' );
		$this->counter->decrement( 'k' );
		$this->assertSame( 0, $this->counter->get( 'k' ) );
		$this->counter->decrement( 'missing' );
	}

	public function test_delete_forgets_the_key(): void {
		$this->counter->add_or_increment( 'k', 60 );
		$this->counter->delete( 'k' );
		$this->assertSame( 0, $this->counter->get( 'k' ) );
		$this->assertSame( 1, $this->counter->add_or_increment( 'k', 60 ) );
	}

	public function test_purge_removes_only_ended_windows(): void {
		global $wpdb;
		$this->counter->add_or_increment( 'old', 10 );
		$this->counter->add_or_increment( 'new', 600 );
		$this->now += 11;
		$this->assertSame( 1, $this->counter->purge_expired() );
		$this->assertSame( '1', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_counters" ) ); // phpcs:ignore WordPress.DB
		$this->assertSame( 1, $this->counter->get( 'new' ) );
	}

	public function test_long_and_odd_keys_are_fine(): void {
		$key = 'login_n:' . str_repeat( 'é', 300 ) . '/64';
		$this->assertSame( 1, $this->counter->add_or_increment( $key, 60 ) );
		$this->assertSame( 2, $this->counter->add_or_increment( $key, 60 ) );
	}

	/** Make one kind of statement fail, as SQLITE_BUSY or a lost connection would. */
	private function break_statements_containing( string $needle ): void {
		global $wpdb;
		$wpdb->suppress_errors( true );
		add_filter(
			'query',
			static fn ( $q ) => str_contains( (string) $q, $needle ) ? 'SELECT nope FROM wpb_no_such_table' : $q
		);
	}

	public function test_a_failing_select_never_answers_one_and_the_whole_operation_falls_back(): void {
		global $wpdb;
		$this->counter->add_or_increment( 'k', 60 );
		$this->counter->add_or_increment( 'k', 60 );
		$this->counter->add_or_increment( 'k', 60 );
		$this->break_statements_containing( 'SELECT hits FROM' );
		try {
			$fallback = new TableCounter( fn (): int => $this->now );
			$this->assertSame( 1, $fallback->add_or_increment( 'k', 60 ), 'counted in the transient fallback, not by the failed read' );
			$this->assertSame( 2, $fallback->add_or_increment( 'k', 60 ) );
			$this->assertNotFalse( get_option( TableCounter::FAILED_OPTION ) );
		} finally {
			remove_all_filters( 'query' );
			$wpdb->suppress_errors( false );
		}
	}

	public function test_a_failing_increment_falls_back(): void {
		global $wpdb;
		$this->break_statements_containing( 'hits = hits + 1' );
		try {
			$c = new TableCounter( fn (): int => $this->now );
			$this->assertSame( 1, $c->add_or_increment( 'j', 60 ) );
			$this->assertSame( 2, $c->add_or_increment( 'j', 60 ) );
		} finally {
			remove_all_filters( 'query' );
			$wpdb->suppress_errors( false );
		}
	}

	public function test_a_failing_window_reset_falls_back(): void {
		global $wpdb;
		$this->break_statements_containing( 'SET hits = 0' );
		try {
			$c = new TableCounter( fn (): int => $this->now );
			$this->assertSame( 1, $c->add_or_increment( 'm', 60 ) );
			$this->assertSame( 2, $c->add_or_increment( 'm', 60 ) );
		} finally {
			remove_all_filters( 'query' );
			$wpdb->suppress_errors( false );
		}
	}

	public function test_a_missing_table_falls_back_to_transients_and_raises_the_flag(): void {
		global $wpdb;
		$this->use_real_ddl();
		$table = $wpdb->prefix . 'bouncer_counters';
		delete_option( TableCounter::FAILED_OPTION );
		$wpdb->query( "RENAME TABLE {$table} TO {$table}_gone" ); // phpcs:ignore WordPress.DB
		$wpdb->suppress_errors( true );
		try {
			$this->assertSame( 1, $this->counter->add_or_increment( 'k', 60 ) );
			$this->assertSame( 2, $this->counter->add_or_increment( 'k', 60 ), 'still counts' );
			$this->assertNotFalse( get_option( TableCounter::FAILED_OPTION ) );
			$this->assertSame( 2, $this->counter->get( 'k' ) );
			$this->counter->decrement( 'k' );
			$this->assertSame( 1, $this->counter->get( 'k' ) );
			// A fresh instance (the next request) finds the same fallback count.
			$next = new TableCounter( fn (): int => $this->now );
			$this->assertSame( 1, $next->get( 'k' ) );
			$next->delete( 'k' );
			$this->assertSame( 0, $next->get( 'k' ) );
		} finally {
			$wpdb->suppress_errors( false );
			$wpdb->query( "RENAME TABLE {$table}_gone TO {$table}" ); // phpcs:ignore WordPress.DB
		}
	}

	public function test_the_flag_notice_shows_while_the_table_is_missing_and_clears_when_it_is_back(): void {
		global $wpdb;
		$this->use_real_ddl();
		$table = $wpdb->prefix . 'bouncer_counters';
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$notices = new \WPBouncer\Admin\DataNotices();
		update_option( TableCounter::FAILED_OPTION, time() );
		$wpdb->query( "RENAME TABLE {$table} TO {$table}_gone" ); // phpcs:ignore WordPress.DB
		try {
			ob_start();
			$notices->render();
			$this->assertStringContainsString( 'login counter table', (string) ob_get_clean() );
		} finally {
			$wpdb->query( "RENAME TABLE {$table}_gone TO {$table}" ); // phpcs:ignore WordPress.DB
		}
		ob_start();
		$notices->render();
		$this->assertSame( '', (string) ob_get_clean() );
		$this->assertFalse( get_option( TableCounter::FAILED_OPTION ) );
		wp_set_current_user( 0 );
	}
}
