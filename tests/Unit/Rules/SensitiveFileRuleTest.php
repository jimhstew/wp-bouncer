<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use WPBouncer\Rules\SensitiveFileRule;
use WPBouncer\Tests\Support\FrozenClock;
use WPBouncer\Tests\Support\MemoryStore;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Rules\SensitiveFileRule
 */
final class SensitiveFileRuleTest extends TestCase {

	private FrozenClock $clock;
	private MemoryStore $store;

	protected function setUp(): void {
		$this->clock = new FrozenClock();
		$this->store = new MemoryStore( $this->clock );
	}

	/** @param array<string, mixed> $settings Overrides. */
	private function rule( array $settings = array() ): SensitiveFileRule {
		return new SensitiveFileRule(
			array_merge(
				array(
					'enabled'     => true,
					'ban_minutes' => 60,
					'extra_paths' => array(),
				),
				$settings
			),
			$this->store
		);
	}

	/** @return array<string, array{0: string}> */
	public static function probes(): array {
		$paths = array(
			'/.env',
			'/.env.production',
			'/app/.env',
			'/.ENV',
			'/.git/config',
			'/.git/HEAD',
			'/.svn/entries',
			'/.htpasswd',
			'/.user.ini',
			'/.DS_Store',
			'/.aws/credentials',
			'/.ssh/id_rsa',
			'/.vscode/sftp.json',
			'/wp-config.php.bak',
			'/wp-config.php~',
			'/wp-config.old',
			'/wp-config.txt',
			'/.wp-config.php.swp',
			'/wp-config.php.save',
			'/index.php.bak',
			'/wp-content/plugins/foo/foo.php.orig',
			'/backup.sql',
			'/dump.sql.gz',
			'/database.sqlite',
			'/backup.zip',
			'/wordpress.tar.gz',
			'/public_html.rar',
			'/wp-content/debug.log',
			'/error_log',
			'/phpinfo.php',
			'/info.php',
			'/adminer.php',
			'/adminer-4.8.1.php',
			'/phpmyadmin/',
			'/phpMyAdmin/index.php',
			'/pma',
			'/wso.php',
			'/wp-content/uploads/2024/01/shell.php',
			'/wp-content/uploads/x.phtml',
			'/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
			'/composer.json',
			'/composer.lock',
			'/package.json',
			'/docker-compose.yml',
			'/server-status',
			'/%2eenv',
		);
		$out   = array();
		foreach ( $paths as $p ) {
			$out[ $p ] = array( $p );
		}
		return $out;
	}

	/** @return array<string, array{0: string}> */
	public static function normal(): array {
		$paths = array(
			'/',
			'/wp-config.php',
			'/wp-config-sample.php',
			'/wp-login.php',
			'/wp-admin/admin-ajax.php',
			'/wp-cron.php',
			'/xmlrpc.php',
			'/index.php',
			'/about-us/',
			'/2024/05/how-to-backup-your-site/',
			'/environment/',
			'/blog/git-tips/',
			'/wp-content/uploads/2024/01/photo.jpg',
			'/wp-content/uploads/report.pdf',
			'/wp-content/plugins/woocommerce/assets/js/frontend.js',
			'/wp-content/themes/twentytwentyfour/style.css',
			'/.well-known/acme-challenge/abc123',
			'/.well-known/security.txt',
			'/sitemap.xml',
			'/robots.txt',
			'/feed/',
			'/wp-json/wp/v2/posts',
			'/shop/backup-generator/',
			'/sql-tutorial/',
			'/information.php',
			'/my-info-page/',
			'/wp-content/uploads/wp-bouncer-test-abc123def456.php',
		);
		$out   = array();
		foreach ( $paths as $p ) {
			$out[ $p ] = array( $p );
		}
		return $out;
	}

	/** @dataProvider probes */
	public function test_probes_are_refused( string $uri ): void {
		$verdict = $this->rule()->inspect( Requests::make( array( 'uri' => $uri ) ) );
		$this->assertNotNull( $verdict, $uri );
		$this->assertSame( 'sensitive_files', $verdict->rule() );
		$this->assertSame( 403, $verdict->status() );
	}

	/** @dataProvider normal */
	public function test_normal_paths_pass( string $uri ): void {
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'uri' => $uri ) ) ), $uri );
	}

	public function test_query_string_is_not_part_of_the_path(): void {
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/?file=.env' ) ) ) );
	}

	public function test_probe_bans_the_ip_from_every_page(): void {
		$rule = $this->rule();
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'uri' => '/.env' ) ) ) );
		$this->assertNull( $rule->inspect( Requests::make( array( 'uri' => '/' ) ) ), 'one probe does not ban' );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'uri' => '/.git/config' ) ) ) );
		$verdict = $rule->inspect( Requests::make( array( 'uri' => '/' ) ) );
		$this->assertNotNull( $verdict );
		$this->assertStringContainsString( 'Banned', $verdict->reason() );
		$this->assertNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri' => '/',
						'ip'  => '198.51.100.9',
					)
				)
			),
			'other IPs unaffected'
		);
	}

	public function test_ban_expires(): void {
		$rule = $this->rule( array( 'ban_minutes' => 5 ) );
		$rule->inspect( Requests::make( array( 'uri' => '/.git/config' ) ) );
		$rule->inspect( Requests::make( array( 'uri' => '/.git/config' ) ) );
		$this->clock->advance( 299 );
		$this->assertNotNull( $rule->inspect( Requests::make() ) );
		$this->clock->advance( 2 );
		$this->assertNull( $rule->inspect( Requests::make() ) );
	}

	public function test_zero_minutes_refuses_only_the_probe(): void {
		$rule = $this->rule( array( 'ban_minutes' => 0 ) );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'uri' => '/.env' ) ) ) );
		$this->assertNull( $rule->inspect( Requests::make() ) );
		$this->assertNull( $this->store->get( SensitiveFileRule::ban_key( '203.0.113.10' ) ) );
	}

	public function test_administrators_are_never_refused_or_banned(): void {
		$rule = $this->rule();
		$this->assertNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri'     => '/.env',
						'trusted' => true,
					)
				)
			)
		);
		$this->assertNull( $this->store->get( SensitiveFileRule::ban_key( '203.0.113.10' ) ) );
	}

	public function test_extra_paths(): void {
		$rule    = $this->rule( array( 'extra_paths' => array( '/old-admin/' ) ) );
		$verdict = $rule->inspect( Requests::make( array( 'uri' => '/Old-Admin/login.php' ) ) );
		$this->assertNotNull( $verdict );
		$this->assertStringContainsString( 'custom path', $verdict->reason() );
	}

	public function test_match_labels(): void {
		$rule = $this->rule();
		$this->assertSame( 'environment file', $rule->match( '/.env' ) );
		$this->assertSame( 'version control data', $rule->match( '/.git/config' ) );
		$this->assertSame( 'database dump', $rule->match( '/db.sql' ) );
		$this->assertNull( $rule->match( '/hello-world/' ) );
	}

	public function test_a_client_that_cannot_be_banned_is_refused_but_no_ban_is_kept(): void {
		$rule = $this->rule();
		$ip   = '127.0.0.1';
		$one  = Requests::make(
			array(
				'ip'       => $ip,
				'uri'      => '/.env',
				'bannable' => false,
			)
		);

		$this->assertNotNull( $rule->inspect( $one ), 'this request is still refused' );
		$this->assertNull( $this->store->get( SensitiveFileRule::ban_key( $ip ) ), 'but no ban key is written' );
		$this->assertNull(
			$rule->inspect(
				Requests::make(
					array(
						'ip'       => $ip,
						'uri'      => '/',
						'bannable' => false,
					)
				)
			),
			'and the next page view is fine'
		);
	}

	public function test_an_existing_ban_is_not_enforced_against_a_client_that_cannot_be_banned(): void {
		$this->store->set( SensitiveFileRule::ban_key( '192.0.2.5' ), 1, 600 );
		$this->assertNull(
			$this->rule()->inspect(
				Requests::make(
					array(
						'ip'       => '192.0.2.5',
						'uri'      => '/',
						'bannable' => false,
					)
				)
			)
		);
		$this->assertNotNull(
			$this->rule()->inspect(
				Requests::make(
					array(
						'ip'  => '192.0.2.5',
						'uri' => '/',
					)
				)
			)
		);
	}

	private static function sec_fetch( string $site, string $dest = '' ): array {
		$server = array( 'HTTP_SEC_FETCH_SITE' => $site );
		if ( '' !== $dest ) {
			$server['HTTP_SEC_FETCH_DEST'] = $dest;
		}
		return $server;
	}

	public function test_cross_site_probes_are_refused_and_ban_only_at_the_higher_limit(): void {
		$rule = $this->rule();
		for ( $i = 1; $i <= 4; $i++ ) {
			$this->assertNotNull(
				$rule->inspect(
					Requests::make(
						array(
							'uri'    => '/.env',
							'server' => self::sec_fetch( 'cross-site', 'image' ),
						)
					)
				),
				'still refused'
			);
			$this->assertNull( $this->store->get( SensitiveFileRule::ban_key( '203.0.113.10' ) ), "no ban after {$i}" );
		}
		$this->assertNull( $this->store->get( SensitiveFileRule::probe_key( '203.0.113.10' ) ), 'the normal bucket is untouched' );
		$this->assertNull( $rule->inspect( Requests::make() ), 'the visitor can still browse' );
		$rule->inspect(
			Requests::make(
				array(
					'uri'    => '/.env',
					'server' => self::sec_fetch( 'cross-site' ),
				)
			)
		);
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'server' => self::sec_fetch( 'cross-site', 'image' ) ) ) ), 'after the fifth, foreign requests are refused' );
		$this->assertNull( $this->store->get( SensitiveFileRule::ban_key( '203.0.113.10' ) ), 'but no site-wide ban' );
	}

	public function test_the_foreign_limit_is_configurable_and_never_below_the_normal_one(): void {
		$rule = $this->rule( array( 'cross_site_probes' => 2 ) );
		$rule->inspect(
			Requests::make(
				array(
					'uri'    => '/.env',
					'server' => self::sec_fetch( 'cross-site' ),
				)
			)
		);
		$rule->inspect(
			Requests::make(
				array(
					'uri'    => '/.env',
					'server' => self::sec_fetch( 'cross-site' ),
				)
			)
		);
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'server' => self::sec_fetch( 'cross-site' ) ) ) ) );
		$low = $this->rule( array( 'cross_site_probes' => 0 ) );
		$low->inspect(
			Requests::make(
				array(
					'ip'     => '198.51.100.7',
					'uri'    => '/.env',
					'server' => self::sec_fetch( 'cross-site' ),
				)
			)
		);
		$this->assertNull( $low->inspect( Requests::make( array( 'ip' => '198.51.100.7' ) ) ), 'a single probe never bans' );
	}

	public function test_a_matching_subresource_load_is_not_counted_but_a_mislabelled_one_is(): void {
		$rule = $this->rule( array( 'extra_paths' => array( '/old.png' ) ) );
		for ( $i = 0; $i < 6; $i++ ) {
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/old.png',
						'server' => self::sec_fetch( 'same-origin', 'image' ),
					)
				)
			);
		}
		$this->assertNull( $rule->inspect( Requests::make() ), 'a real image load never counts' );
		for ( $i = 0; $i < 5; $i++ ) {
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/.env',
						'server' => self::sec_fetch( 'same-site', 'image' ),
					)
				)
			);
		}
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'server' => self::sec_fetch( 'cross-site' ) ) ) ), '"/.env" is not an image: it counts as a foreign probe' );
		$this->assertNull( $this->store->get( SensitiveFileRule::ban_key( '203.0.113.10' ) ), 'in the foreign bucket, so no site-wide ban' );
	}

	public function test_probe_counts_use_the_atomic_counter_when_given_one(): void {
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
		$rule    = new SensitiveFileRule(
			array(
				'enabled'     => true,
				'ban_minutes' => 60,
			),
			$this->store,
			$counter
		);
		$rule->inspect( Requests::make( array( 'uri' => '/.env' ) ) );
		$this->assertSame( 1, $counter->get( SensitiveFileRule::probe_key( '203.0.113.10' ) ) );
		$rule->inspect( Requests::make( array( 'uri' => '/.env' ) ) );
		$this->assertNotNull( $this->store->get( SensitiveFileRule::ban_key( '203.0.113.10' ) ) );
		$this->assertSame( 0, $counter->get( SensitiveFileRule::probe_key( '203.0.113.10' ) ), 'counter cleared after the ban' );
	}

	public function test_a_stored_ban_length_above_24_hours_is_capped(): void {
		$rule = $this->rule( array( 'ban_minutes' => 43200 ) );
		$rule->inspect( Requests::make( array( 'uri' => '/.env' ) ) );
		$rule->inspect( Requests::make( array( 'uri' => '/.env' ) ) );
		$this->clock->advance( 1440 * 60 + 1 );
		$this->assertNull( $rule->inspect( Requests::make() ) );
	}

	public function test_two_same_site_probes_ban_and_a_single_one_does_not(): void {
		$one = $this->rule();
		$one->inspect(
			Requests::make(
				array(
					'uri'    => '/.env',
					'ip'     => '198.51.100.1',
					'server' => self::sec_fetch( 'same-site' ),
				)
			)
		);
		$this->assertNull( $one->inspect( Requests::make( array( 'ip' => '198.51.100.1' ) ) ) );
		$two = $this->rule();
		$two->inspect(
			Requests::make(
				array(
					'uri'    => '/.env',
					'ip'     => '198.51.100.2',
					'server' => self::sec_fetch( 'same-site' ),
				)
			)
		);
		$two->inspect(
			Requests::make(
				array(
					'uri'    => '/.env',
					'ip'     => '198.51.100.2',
					'server' => self::sec_fetch( 'none' ),
				)
			)
		);
		$this->assertNotNull( $two->inspect( Requests::make( array( 'ip' => '198.51.100.2' ) ) ) );
	}

	public function test_probes_outside_the_window_do_not_add_up(): void {
		$rule = $this->rule();
		$rule->inspect( Requests::make( array( 'uri' => '/.env' ) ) );
		$this->clock->advance( SensitiveFileRule::BAN_WINDOW + 1 );
		$rule->inspect( Requests::make( array( 'uri' => '/.env' ) ) );
		$this->assertNull( $rule->inspect( Requests::make() ) );
	}

	public function test_a_framed_visitor_can_still_browse_and_a_header_forging_scanner_is_refused(): void {
		$rule = $this->rule();
		// A hostile page makes the visitor's browser fire probes (five image tags), each labelled cross-site.
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertNotNull(
				$rule->inspect(
					Requests::make(
						array(
							'uri'    => '/.env',
							'server' => self::sec_fetch( 'cross-site', 'image' ),
						)
					)
				)
			);
		}
		$this->assertNull( $this->store->get( SensitiveFileRule::ban_key( '203.0.113.10' ) ), 'no site-wide ban' );
		foreach ( array(
			'no headers'    => array(),
			'same-origin'   => self::sec_fetch( 'same-origin' ),
			'typed address' => self::sec_fetch( 'none' ),
			'link click'    => array_merge( self::sec_fetch( 'cross-site', 'document' ), array( 'HTTP_SEC_FETCH_MODE' => 'navigate' ) ),
		) as $label => $server ) {
			$this->assertNull(
				$rule->inspect(
					Requests::make(
						array(
							'uri'    => '/',
							'server' => $server,
						)
					)
				),
				$label
			);
		}
		// A scanner that forges the header on every request is refused on every one of them.
		$this->assertNotNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/',
						'server' => self::sec_fetch( 'cross-site' ),
					)
				)
			)
		);
		$this->assertNotNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/wp-login.php',
						'server' => self::sec_fetch( 'cross-site', 'image' ),
					)
				)
			)
		);
		// One that sends no header at all hits the normal bucket and is banned site-wide.
		$rule->inspect(
			Requests::make(
				array(
					'ip'  => '198.51.100.20',
					'uri' => '/.env',
				)
			)
		);
		$rule->inspect(
			Requests::make(
				array(
					'ip'  => '198.51.100.20',
					'uri' => '/.env',
				)
			)
		);
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'ip' => '198.51.100.20' ) ) ) );
	}

	public function test_the_foreign_refusal_lasts_for_the_ban_period(): void {
		$rule = $this->rule( array( 'ban_minutes' => 5 ) );
		for ( $i = 0; $i < 5; $i++ ) {
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/.env',
						'server' => self::sec_fetch( 'cross-site' ),
					)
				)
			);
		}
		$this->clock->advance( 299 );
		$this->assertNotNull( $rule->inspect( Requests::make( array( 'server' => self::sec_fetch( 'cross-site' ) ) ) ) );
		$this->clock->advance( 2 );
		$this->assertNull( $rule->inspect( Requests::make( array( 'server' => self::sec_fetch( 'cross-site' ) ) ) ) );
	}

	public function test_a_cross_site_navigation_counts_in_the_normal_bucket_and_a_forging_scanner_is_banned(): void {
		$rule = $this->rule();
		$nav  = array_merge( self::sec_fetch( 'cross-site', 'document' ), array( 'HTTP_SEC_FETCH_MODE' => 'navigate' ) );
		$rule->inspect(
			Requests::make(
				array(
					'uri'    => '/.env',
					'server' => $nav,
				)
			)
		);
		$this->assertNull( $rule->inspect( Requests::make() ), 'one navigation does not ban' );
		$rule->inspect(
			Requests::make(
				array(
					'uri'    => '/.env',
					'server' => $nav,
				)
			)
		);
		$this->assertNotNull( $this->store->get( SensitiveFileRule::ban_key( '203.0.113.10' ) ), 'two do, as for a headerless request' );
		$this->assertNotNull( $rule->inspect( Requests::make() ) );
	}

	public function test_the_foreign_refusal_does_not_touch_the_visitors_own_dynamic_assets(): void {
		$rule = $this->rule();
		for ( $i = 0; $i < 5; $i++ ) {
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/.env',
						'server' => self::sec_fetch( 'cross-site', 'image' ),
					)
				)
			);
		}
		$this->assertNotNull(
			$rule->inspect(
				Requests::make(
					array(
						'uri'    => '/x',
						'server' => self::sec_fetch( 'cross-site', 'image' ),
					)
				)
			),
			'the foreign refusal is active'
		);
		foreach ( array( '/wp-admin/load-scripts.php', '/wp-admin/load-styles.php', '/captcha.php', '/dynamic.css.php' ) as $uri ) {
			$this->assertNull(
				$rule->inspect(
					Requests::make(
						array(
							'uri'    => $uri,
							'server' => self::sec_fetch( 'same-origin', 'script' ),
						)
					)
				),
				$uri
			);
		}
	}
}
