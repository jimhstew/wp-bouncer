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
		$this->assertNull(
			$this->miss(
				$rule,
				50,
				array(
					'ip'       => '127.0.0.1',
					'bannable' => false,
				)
			)
		);
		$this->assertNull( $this->store->get( NotFoundFloodRule::ban_key( '127.0.0.1' ) ) );
		$this->assertNull( $this->store->get( NotFoundFloodRule::counter_key( '127.0.0.1' ) ) );
	}

	public function test_an_existing_ban_is_not_enforced_against_a_client_that_cannot_be_banned(): void {
		$this->store->set( NotFoundFloodRule::ban_key( '192.0.2.5' ), 1, 600 );
		$rule = $this->rule();
		$this->assertNull(
			$rule->inspect(
				Requests::make(
					array(
						'ip'       => '192.0.2.5',
						'bannable' => false,
					)
				)
			)
		);
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '192.0.2.5' ) ) ) );
	}

	public function test_cross_site_404s_have_their_own_higher_limit(): void {
		$rule  = $this->rule();
		$cross = array( 'server' => array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$this->assertNull( $this->miss( $rule, 25, $cross ), '5 x the limit of 5 is allowed' );
		$this->assertNull( $this->store->get( NotFoundFloodRule::counter_key( '203.0.113.10' ) ), 'the normal counter is untouched' );
		$this->assertNull( $rule->inspect( Requests::make( $cross ) ) );
		$this->assertNotNull( $this->miss( $rule, 1, $cross ), 'the 26th trips the foreign limit' );
		$this->assertNotNull( $rule->inspect( Requests::make( $cross ) ), 'foreign requests are refused' );
		$this->assertNull( $rule->inspect( Requests::make() ), 'the visitor\'s own requests are not' );
		$this->assertNull( $this->store->get( NotFoundFloodRule::ban_key( '203.0.113.10' ) ), 'no site-wide ban' );
	}

	public function test_the_multiplier_is_configurable(): void {
		$rule  = $this->rule( array( 'cross_site_multiplier' => 2 ) );
		$cross = array( 'server' => array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$this->assertNull( $this->miss( $rule, 10, $cross ) );
		$this->assertNotNull( $this->miss( $rule, 1, $cross ) );
		$this->assertNotNull( $rule->inspect( Requests::make( $cross ) ) );
	}

	public function test_matching_subresource_404s_are_not_counted_and_mislabelled_ones_count_as_foreign(): void {
		$rule = $this->rule();
		$this->assertFalse(
			$rule->counts(
				Requests::make(
					array(
						'uri'    => '/missing.png',
						'server' => array( 'HTTP_SEC_FETCH_DEST' => 'image' ),
					)
				)
			)
		);
		$mislabelled = Requests::make(
			array(
				'uri'    => '/some-page/',
				'server' => array(
					'HTTP_SEC_FETCH_SITE' => 'same-site',
					'HTTP_SEC_FETCH_DEST' => 'image',
				),
			)
		);
		$this->assertTrue( $rule->counts( $mislabelled ) );
		$this->assertTrue( $mislabelled->is_foreign_fetch(), 'a same-site "image" that is not an image' );
		// The visitor's own dynamic scripts and styles are not foreign, whatever the file type.
		foreach ( array( 'same-origin', 'none' ) as $site ) {
			$own = Requests::make(
				array(
					'uri'    => '/wp-admin/load-scripts.php',
					'server' => array(
						'HTTP_SEC_FETCH_SITE' => $site,
						'HTTP_SEC_FETCH_DEST' => 'script',
					),
				)
			);
			$this->assertFalse( $own->is_foreign_fetch(), $site );
		}
		// With no Sec-Fetch-Site at all, a forged destination alone doesn't make a request foreign: it is in the normal bucket.
		$this->assertFalse(
			Requests::make(
				array(
					'uri'    => '/.env',
					'server' => array( 'HTTP_SEC_FETCH_DEST' => 'image' ),
				)
			)->is_foreign_fetch()
		);
	}

	public function test_a_cross_site_navigation_counts_in_the_normal_bucket(): void {
		$rule = $this->rule();
		$nav  = array(
			'server' => array(
				'HTTP_SEC_FETCH_SITE' => 'cross-site',
				'HTTP_SEC_FETCH_MODE' => 'navigate',
				'HTTP_SEC_FETCH_DEST' => 'document',
			),
		);
		$this->assertFalse( Requests::make( $nav )->is_foreign_fetch() );
		// A scanner that forges navigation headers on every request earns the ordinary site-wide ban.
		$this->assertNull( $this->miss( $rule, 5, $nav ) );
		$this->assertNotNull( $this->miss( $rule, 1, $nav ) );
		$this->assertNotNull( $rule->inspect( Requests::make() ), 'site-wide' );
		$this->assertNotNull( $this->store->get( NotFoundFloodRule::ban_key( '203.0.113.10' ) ) );
	}

	public function test_the_foreign_refusal_does_not_touch_the_visitors_own_dynamic_assets(): void {
		$rule  = $this->rule();
		$cross = array( 'server' => array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$this->miss( $rule, 26, $cross );
		$this->assertNotNull( $rule->inspect( Requests::make( $cross ) ), 'the foreign refusal is active' );
		foreach ( array( '/wp-admin/load-scripts.php', '/wp-admin/load-styles.php', '/captcha.php', '/dynamic.css.php' ) as $uri ) {
			$request = Requests::make(
				array(
					'uri'    => $uri,
					'server' => array(
						'HTTP_SEC_FETCH_SITE' => 'same-origin',
						'HTTP_SEC_FETCH_DEST' => 'script',
					),
				)
			);
			$this->assertNull( $rule->inspect( $request ), $uri );
		}
	}

	public function test_origin_header_stands_in_when_sec_fetch_is_missing(): void {
		$rule = $this->rule();
		$this->assertNull(
			$this->miss(
				$rule,
				25,
				array(
					'server'    => array( 'HTTP_ORIGIN' => 'https://evil.example' ),
					'own_hosts' => array( 'shop.example' ),
				)
			)
		);
		$this->assertNotNull(
			$this->miss(
				$rule,
				6,
				array(
					'server'    => array( 'HTTP_ORIGIN' => 'https://shop.example' ),
					'own_hosts' => array( 'shop.example' ),
				)
			)
		);
	}

	public function test_own_hosts_may_be_a_callable_evaluated_lazily(): void {
		$calls   = 0;
		$request = Requests::make(
			array(
				'server'    => array( 'HTTP_ORIGIN' => 'https://late.example' ),
				'own_hosts' => static function () use ( &$calls ): array {
					++$calls;
					return array( 'late.example' );
				},
			)
		);
		$this->assertSame( 0, $calls, 'not evaluated on construction' );
		$this->assertSame( 'same-origin', $request->fetch_context() );
		$request->fetch_context();
		$this->assertSame( 2, $calls, 'a closure is re-read each time, so late filters apply and nothing stale is kept' );
	}

	public function test_atomic_counter_is_used_when_given(): void {
		$counter = new class() implements \WPBouncer\Storage\AtomicCounterInterface {
			public array $counts = array();
			public function add_or_increment( string $key, int $ttl ): int {
				$this->counts[ $key ] = ( $this->counts[ $key ] ?? 0 ) + 1;
				return $this->counts[ $key ];
			}
			public function decrement( string $key ): void {}
			public function get( string $key ): int {
				return $this->counts[ $key ] ?? 0;
			}
			public function delete( string $key ): void {
				unset( $this->counts[ $key ] );
			}
		};
		$rule    = new NotFoundFloodRule(
			array(
				'enabled'         => true,
				'max_404'         => 5,
				'window_seconds'  => 60,
				'ban_minutes'     => 10,
				'ignore_crawlers' => false,
			),
			$this->store,
			$counter
		);
		$this->miss( $rule, 3 );
		$this->assertSame( 3, $counter->get( NotFoundFloodRule::counter_key( '203.0.113.10' ) ) );
		$this->miss( $rule, 3 );
		$this->assertNotNull( $this->store->get( NotFoundFloodRule::ban_key( '203.0.113.10' ) ) );
	}

	public function test_a_framed_visitor_with_101_foreign_404s_can_still_browse_and_a_forging_scanner_is_refused(): void {
		$rule  = $this->rule();
		$cross = array( 'server' => array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ) );
		$this->miss( $rule, 101, $cross );
		$this->assertNull( $this->store->get( NotFoundFloodRule::ban_key( '203.0.113.10' ) ), 'no site-wide ban' );
		$this->assertNull( $rule->inspect( Requests::make() ), 'no headers' );
		$this->assertNull( $rule->inspect( Requests::make( array( 'server' => array( 'HTTP_SEC_FETCH_SITE' => 'same-origin' ) ) ) ), 'same-origin' );
		$this->assertNull(
			$rule->inspect(
				Requests::make(
					array(
						'server' => array(
							'HTTP_SEC_FETCH_SITE' => 'cross-site',
							'HTTP_SEC_FETCH_MODE' => 'navigate',
							'HTTP_SEC_FETCH_DEST' => 'document',
						),
					)
				)
			),
			'following a link'
		);
		$this->assertNotNull( $rule->inspect( Requests::make( $cross ) ), 'a forged header is refused every time' );
		// Without the header the scanner is in the normal bucket and gets the site-wide ban.
		$this->miss( $rule, 6, array( 'ip' => '198.51.100.21' ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '198.51.100.21' ) ) ) );
	}
}
