<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use WPBouncer\Rules\NotFoundFloodRule;
use WPBouncer\Tests\Support\FrozenClock;
use WPBouncer\Tests\Support\MemoryStore;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Rules\NotFoundFloodRule
 */
final class NotFoundFloodRuleTest extends TestCase {

	private FrozenClock $clock;
	private MemoryStore $store;

	protected function setUp(): void {
		$this->clock = new FrozenClock();
		$this->store = new MemoryStore( $this->clock );
	}

	/** @param array<string, mixed> $settings Overrides. */
	private function rule( array $settings = array() ): NotFoundFloodRule {
		return new NotFoundFloodRule(
			array_merge(
				array(
					'enabled'         => true,
					'max_404'         => 5,
					'window_seconds'  => 60,
					'ban_minutes'     => 10,
					'ignore_crawlers' => true,
				),
				$settings
			),
			$this->store
		);
	}

	/** @param array<string, mixed> $args Request args. */
	private function miss( NotFoundFloodRule $rule, int $times, array $args = array() ): ?string {
		$reason = null;
		for ( $i = 0; $i < $times; $i++ ) {
			$reason = $rule->record( Requests::make( array_merge( array( 'uri' => '/wp-content/plugins/scan-' . $i . '/readme.txt' ), $args ) ) );
		}
		return $reason;
	}

	public function test_bans_after_the_limit(): void {
		$rule = $this->rule();
		$this->assertNull( $this->miss( $rule, 5 ), 'five are allowed' );
		$this->assertNull( $rule->inspect( Requests::make() ) );
		$reason = $this->miss( $rule, 1 );
		$this->assertNotNull( $reason );
		$this->assertStringContainsString( '10 minutes', $reason );
		$verdict = $rule->inspect( Requests::make() );
		$this->assertNotNull( $verdict );
		$this->assertSame( 'not_found', $verdict->rule() );
		$this->assertSame( 600, $verdict->retry_after() );
	}

	public function test_ban_expires(): void {
		$rule = $this->rule();
		$this->miss( $rule, 6 );
		$this->clock->advance( 599 );
		$this->assertNotNull( $rule->inspect( Requests::make() ) );
		$this->clock->advance( 2 );
		$this->assertNull( $rule->inspect( Requests::make() ) );
	}

	public function test_counter_resets_each_window(): void {
		$rule = $this->rule();
		$this->miss( $rule, 5 );
		$this->clock->advance( 61 );
		$this->assertNull( $this->miss( $rule, 5 ) );
	}

	public function test_missing_assets_do_not_count(): void {
		$rule = $this->rule();
		foreach ( array( '/a.jpg', '/b.PNG', '/c.css', '/d.js', '/e.woff2', '/f.svg', '/g.webp', '/h.map', '/i.ico', '/j.mp4', '/k.pdf' ) as $uri ) {
			$this->assertFalse( $rule->counts( Requests::make( array( 'uri' => $uri ) ) ), $uri );
		}
		for ( $i = 0; $i < 50; $i++ ) {
			$this->assertNull( $rule->record( Requests::make( array( 'uri' => "/img/{$i}.jpg" ) ) ) );
		}
		$this->assertNull( $rule->inspect( Requests::make() ) );
	}

	public function test_scanner_targets_do_count(): void {
		$rule = $this->rule();
		foreach ( array( '/wp-content/plugins/x/readme.txt', '/old-page/', '/config.json', '/sitemap-old.xml', '/vuln.php' ) as $uri ) {
			$this->assertTrue( $rule->counts( Requests::make( array( 'uri' => $uri ) ) ), $uri );
		}
	}

	public function test_crawlers_are_ignored_when_set(): void {
		$googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
		$this->assertFalse( $this->rule()->counts( Requests::make( array( 'ua' => $googlebot ) ) ) );
		$this->assertTrue( $this->rule( array( 'ignore_crawlers' => false ) )->counts( Requests::make( array( 'ua' => $googlebot ) ) ) );
	}

	public function test_administrators_are_not_counted_or_refused(): void {
		$rule = $this->rule();
		$this->assertNull( $this->miss( $rule, 20, array( 'trusted' => true ) ) );
		$this->miss( $rule, 6 );
		$this->assertNull( $rule->inspect( Requests::make( array( 'trusted' => true ) ) ) );
	}

	public function test_disabled_rule_does_not_count(): void {
		$rule = $this->rule( array( 'enabled' => false ) );
		$this->assertNull( $this->miss( $rule, 20 ) );
		$this->assertNull( $this->store->get( NotFoundFloodRule::ban_key( '203.0.113.10' ) ) );
	}

	public function test_ips_are_independent(): void {
		$rule = $this->rule();
		$this->miss( $rule, 6 );
		$this->assertNull( $rule->inspect( Requests::make( array( 'ip' => '198.51.100.7' ) ) ) );
	}

	public function test_404s_from_a_client_that_cannot_be_banned_are_not_counted(): void {
		$rule = $this->rule();
		$this->assertNull( $this->miss( $rule, 50, array( 'ip' => '127.0.0.1', 'bannable' => false ) ) );
		$this->assertNull( $this->store->get( NotFoundFloodRule::ban_key( '127.0.0.1' ) ) );
		$this->assertNull( $this->store->get( NotFoundFloodRule::counter_key( '127.0.0.1' ) ) );
	}

	public function test_an_existing_ban_is_not_enforced_against_a_client_that_cannot_be_banned(): void {
		$this->store->set( NotFoundFloodRule::ban_key( '192.0.2.5' ), 1, 600 );
		$rule = $this->rule();
		$this->assertNull( $rule->inspect( Requests::make( array( 'ip' => '192.0.2.5', 'bannable' => false ) ) ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '192.0.2.5' ) ) ) );
	}
}
