<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use WPBouncer\Rules\NotFoundFloodRule;
use WPBouncer\Rules\RateLimitRule;
use WPBouncer\Rules\SensitiveFileRule;
use WPBouncer\Firewall\Firewall;
use WPBouncer\Tests\Support\FrozenClock;
use WPBouncer\Tests\Support\MemoryBlockLog;
use WPBouncer\Storage\CounterStoreInterface;
use WPBouncer\Support\CounterSubject;
use WPBouncer\Tests\Support\MemoryStore;
use WPBouncer\Log\BudgetedBlockLog;
use WPBouncer\Log\WriteBudget;
use WPBouncer\Tests\Support\RecordingResponder;
use WPBouncer\Tests\Support\Requests;

/**
 * RT-07: rate limit, 404 flood, sensitive-file probes and the log de-dup key count IPv6 per /64.
 *
 * @covers \WPBouncer\Rules\RateLimitRule
 * @covers \WPBouncer\Rules\NotFoundFloodRule
 * @covers \WPBouncer\Rules\SensitiveFileRule
 * @covers \WPBouncer\Firewall\Firewall
 */
final class CounterSubjectRulesTest extends TestCase {

	private FrozenClock $clock;

	private CountingStore $store;

	protected function setUp(): void {
		$this->clock = new FrozenClock();
		$this->store = new CountingStore( new MemoryStore( $this->clock ) );
	}

	/** Five addresses in 2001:db8:1:2::/64, then others. */
	private static function in_net( int $i, string $net = '2001:db8:1:2' ): string {
		return $net . '::' . dechex( $i + 1 );
	}

	private function rate(): RateLimitRule {
		return new RateLimitRule(
			array(
				'enabled'        => true,
				'max_requests'   => 5,
				'window_seconds' => 60,
				'ban_minutes'    => 5,
			),
			$this->store
		);
	}

	private function nf(): NotFoundFloodRule {
		return new NotFoundFloodRule(
			array(
				'enabled'        => true,
				'max_404'        => 4,
				'window_seconds' => 60,
				'ban_minutes'    => 5,
			),
			$this->store
		);
	}

	private function sf(): SensitiveFileRule {
		return new SensitiveFileRule(
			array(
				'enabled'     => true,
				'ban_minutes' => 60,
			),
			$this->store
		);
	}

	private function req( string $ip, string $uri = '/' ) {
		return Requests::make(
			array(
				'ip'  => $ip,
				'uri' => $uri,
			)
		);
	}

	public function test_rate_limit_shares_the_count_across_a_64_and_bans_the_neighbour(): void {
		$rule = $this->rate();
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertNull( $rule->inspect( $this->req( self::in_net( $i ) ) ) );
		}
		$this->assertNotNull( $rule->inspect( $this->req( self::in_net( 5 ) ) ), 'sixth address in the /64 goes over' );
		$this->assertNotNull( $rule->inspect( $this->req( '2001:db8:1:2:ffff::9' ) ), 'ban covers the /64' );
		$this->assertNull( $rule->inspect( $this->req( '2001:db8:1:3::1' ) ), 'another /64 is independent' );
		$this->assertSame( 1, $this->count_keys( 'rl_ban:' ), 'one ban key, one read on the hot path' );
	}

	public function test_rate_limit_ipv4_mapped_equals_ipv4(): void {
		$rule = $this->rate();
		for ( $i = 0; $i < 5; $i++ ) {
			$rule->inspect( $this->req( 0 === $i % 2 ? '203.0.113.5' : '::ffff:203.0.113.5' ) );
		}
		$this->assertNotNull( $rule->inspect( $this->req( '::ffff:203.0.113.5' ) ) );
		$this->assertNotNull( $rule->inspect( $this->req( '203.0.113.5' ) ) );
	}

	public function test_nothing_is_counted_for_loopback(): void {
		$rule = $this->rate();
		for ( $i = 0; $i < 20; $i++ ) {
			$this->assertNull( $rule->inspect( $this->req( '::1' ) ) );
		}
		$this->assertSame( 0, $this->count_keys( 'rl_' ) );
	}

	public function test_not_found_shares_the_count_and_the_ban_across_a_64(): void {
		$rule   = $this->nf();
		$reason = null;
		for ( $i = 0; $i < 5; $i++ ) {
			$reason = $rule->record( $this->req( self::in_net( $i ), '/scan-' . $i . '/readme.txt' ) );
		}
		$this->assertNotNull( $reason );
		$this->assertNotNull( $rule->inspect( $this->req( '2001:db8:1:2:aaaa::1' ) ) );
		$this->assertNull( $rule->inspect( $this->req( '2001:db8:1:9::1' ) ) );
		$this->assertNull( $rule->record( $this->req( '2001:db8:1:9::1', '/x/readme.txt' ) ), 'second /64 starts at zero' );
	}

	public function test_not_found_ipv4_mapped_equals_ipv4_and_loopback_is_not_counted(): void {
		$rule   = $this->nf();
		$reason = null;
		for ( $i = 0; $i < 5; $i++ ) {
			$reason = $rule->record( $this->req( 0 === $i % 2 ? '198.51.100.7' : '::ffff:198.51.100.7', '/s' . $i . '/a.txt' ) );
		}
		$this->assertNotNull( $reason );
		for ( $i = 0; $i < 10; $i++ ) {
			$this->assertNull( $rule->record( $this->req( '::1', '/s' . $i . '/a.txt' ) ) );
		}
	}

	public function test_sensitive_files_share_probes_and_ban_across_a_64(): void {
		$rule = $this->sf();
		$this->assertNotNull( $rule->inspect( $this->req( self::in_net( 0 ), '/.env' ) ) );
		$this->assertNotNull( $rule->inspect( $this->req( self::in_net( 1 ), '/.git/config' ) ), 'second probe from a neighbour bans' );
		$verdict = $rule->inspect( $this->req( self::in_net( 7 ) ) );
		$this->assertNotNull( $verdict );
		$this->assertStringContainsString( 'Banned', $verdict->reason() );
		$this->assertNull( $rule->inspect( $this->req( '2001:db8:1:3::1' ) ), 'another /64 is independent' );
	}

	public function test_sensitive_files_ipv4_mapped_equals_ipv4(): void {
		$rule = $this->sf();
		$rule->inspect( $this->req( '203.0.113.9', '/.env' ) );
		$rule->inspect( $this->req( '::ffff:203.0.113.9', '/.env' ) );
		$this->assertNotNull( $rule->inspect( $this->req( '203.0.113.9' ) ) );
	}

	public function test_foreign_ban_keys_are_subject_keys(): void {
		$this->assertSame( SensitiveFileRule::foreign_ban_key( '2001:db8:1:2::1' ), SensitiveFileRule::foreign_ban_key( '2001:db8:1:2::ffff' ) );
		$this->assertSame( NotFoundFloodRule::foreign_ban_key( '2001:db8:1:2::1' ), NotFoundFloodRule::foreign_ban_key( '2001:db8:1:2::ffff' ) );
		$this->assertSame( 'sf_xban:2001:db8:1:2::/64', SensitiveFileRule::foreign_ban_key( '2001:db8:1:2::5' ) );
		$this->assertSame( 'nf_count_x:203.0.113.5', NotFoundFloodRule::foreign_counter_key( '::ffff:203.0.113.5' ) );
	}

	public function test_keys_include_the_canonical_form_of_a_typed_address(): void {
		$keys = CounterSubject::keys( '2001:DB8:1:2:0:0:0:5' );
		$this->assertContains( '2001:db8:1:2::5', $keys );
		$this->assertContains( '2001:db8:1:2::/64', $keys );
		$this->assertContains( '2001:DB8:1:2:0:0:0:5', $keys );
		$this->assertContains( '203.0.113.5', CounterSubject::keys( '::ffff:203.0.113.5' ) );
	}

	public function test_log_dedupe_is_per_64(): void {
		$log       = new MemoryBlockLog();
		$responder = new RecordingResponder();
		$rule      = $this->sf();
		$fw        = new Firewall( array( $rule ), array(), false, $log, $this->store );
		$fw->handle( $this->req( self::in_net( 0 ), '/.env' ), $responder, '' );
		$fw->handle( $this->req( self::in_net( 1 ), '/.env' ), $responder, '' );
		$this->assertCount( 1, $log->entries, 'neighbours in a /64 share the de-dup key' );
		$this->assertSame( self::in_net( 0 ), $log->entries[0]['ip'], 'the row keeps the full address' );
		$fw->handle( $this->req( '2001:db8:9::1', '/.env' ), $responder, '' );
		$this->assertCount( 2, $log->entries );
	}

	private function count_keys( string $prefix ): int {
		return count(
			array_filter(
				$this->store->live,
				static fn( string $key ): bool => 0 === strpos( $key, $prefix )
			)
		);
	}

	public function test_a_clean_request_does_one_store_read_per_rule(): void {
		foreach ( array( '203.0.113.5', '2001:db8:1:2::9' ) as $ip ) {
			foreach ( array( $this->rate(), $this->nf(), $this->sf() ) as $rule ) {
				$before = $this->store->gets;
				$this->assertNull( $rule->inspect( $this->req( $ip ) ) );
				$this->assertSame( 1, $this->store->gets - $before, get_class( $rule ) . ' ' . $ip );
			}
		}
	}

	public function test_foreign_probes_ban_foreign_requests_across_a_64(): void {
		$rule  = $this->sf();
		$cross = array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' );
		for ( $i = 0; $i < 5; $i++ ) {
			$rule->inspect( Requests::make( array( 'ip' => self::in_net( $i ), 'uri' => '/.env', 'server' => $cross ) ) );
		}
		$this->assertSame( 1, $this->count_keys( 'sf_xban:2001:db8:1:2::/64' ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '2001:db8:1:2:9::1', 'server' => $cross ) ) ), 'a neighbour is refused for foreign requests' );
		$this->assertNull( $rule->inspect( $this->req( '2001:db8:1:2:9::1' ) ), 'but its own requests pass' );
		$this->assertNull( $rule->inspect( Requests::make( array( 'ip' => '2001:db8:1:3::1', 'server' => $cross ) ) ), 'another /64 is untouched' );
	}

	public function test_foreign_404s_ban_foreign_requests_across_a_64(): void {
		$rule  = $this->nf();
		$cross = array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' );
		for ( $i = 0; $i < 21; $i++ ) {
			$rule->record( Requests::make( array( 'ip' => self::in_net( $i ), 'uri' => '/s' . $i . '/a.txt', 'server' => $cross ) ) );
		}
		$this->assertSame( 1, $this->count_keys( 'nf_xban:2001:db8:1:2::/64' ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '2001:db8:1:2:9::1', 'server' => $cross ) ) ) );
		$this->assertNull( $rule->inspect( $this->req( '2001:db8:1:2:9::1' ) ) );
	}

	public function test_log_dropped_marker_is_per_64(): void {
		$budget = new WriteBudget( $this->store, $this->clock, 1 );
		$log    = new BudgetedBlockLog( new MemoryBlockLog(), $budget );
		$fw     = new Firewall( array( $this->sf() ), array(), false, $log, $this->store, null, $budget );
		for ( $i = 0; $i < 3; $i++ ) {
			$fw->handle( $this->req( '2001:db8:7:' . $i . '::1', '/.env' ), new RecordingResponder(), '' );
		}
		$this->assertGreaterThan( 0, $this->count_keys( 'log_dropped:' ), 'over budget: markers are written' );
		$before = $this->count_keys( 'log_dropped:' );
		$fw->handle( $this->req( '2001:db8:7:2::99', '/.env' ), new RecordingResponder(), '' );
		$this->assertSame( $before, $this->count_keys( 'log_dropped:' ), 'a neighbour in the same /64 reuses the marker' );
		$this->assertContains( 'log_dropped:sensitive_files:2001:db8:7:2::/64', $this->store->live );
	}

	public function test_unlock_keys_clear_every_family_for_any_spelling(): void {
		$families = array( 'rl_ban', 'rl_count', 'sf_ban', 'sf_probe', 'sf_probe_x', 'sf_xban', 'nf_ban', 'nf_count', 'nf_count_x', 'nf_xban' );
		$typed    = array( '2001:DB8:1:2:0:0:0:5', '2001:db8:1:2::5', '2001:db8:1:2::/64' );
		foreach ( $typed as $spelling ) {
			foreach ( $families as $family ) {
				$this->store->set( $family . ':' . $spelling, 1, 600 );
				$this->store->set( $family . ':' . CounterSubject::key( '2001:db8:1:2::77' ), 1, 600 );
			}
			$this->store->set( 'log_seen:rate_limit:' . $spelling, 1, 600 );
		}
		$keys = array_merge(
			RateLimitRule::keys_for( '2001:DB8:1:2:0:0:0:5' ),
			SensitiveFileRule::keys_for( '2001:DB8:1:2:0:0:0:5' ),
			NotFoundFloodRule::keys_for( '2001:DB8:1:2:0:0:0:5' ),
			Firewall::log_keys( '2001:DB8:1:2:0:0:0:5', array( 'rate_limit' ) )
		);
		foreach ( $keys as $key ) {
			$this->store->delete( $key );
		}
		foreach ( $this->store->live as $key ) {
			$this->assertStringNotContainsString( '2001:db8:1:2::/64', $key );
			$this->assertStringNotContainsString( '2001:DB8:1:2:0:0:0:5', $key );
			$this->assertStringNotContainsString( '2001:db8:1:2::5', $key );
		}
		$this->assertSame( array(), $this->store->live, $this->store_dump() );
	}

	private function store_dump(): string {
		return implode( ',', $this->store->live );
	}
}

/** Store decorator that counts reads and tracks which keys are present. */
final class CountingStore implements CounterStoreInterface {

	public int $gets = 0;

	/** @var string[] */
	public array $live = array();

	private MemoryStore $inner;

	public function __construct( MemoryStore $inner ) {
		$this->inner = $inner;
	}

	public function get( string $key ) {
		++$this->gets;
		return $this->inner->get( $key );
	}

	public function set( string $key, $value, int $ttl ): void {
		$this->live[ $key ] = $key;
		$this->live         = array_values( array_unique( $this->live ) );
		$this->inner->set( $key, $value, $ttl );
	}

	public function increment( string $key, int $ttl ): int {
		if ( null === $this->inner->get( $key ) ) {
			$this->live[] = $key;
		}
		return $this->inner->increment( $key, $ttl );
	}

	public function delete( string $key ): void {
		$this->live = array_values( array_diff( $this->live, array( $key ) ) );
		$this->inner->delete( $key );
	}
}
