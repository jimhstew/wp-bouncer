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
		$out = array();
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
		$out = array();
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
		$verdict = $rule->inspect( Requests::make( array( 'uri' => '/' ) ) );
		$this->assertNotNull( $verdict );
		$this->assertStringContainsString( 'Banned', $verdict->reason() );
		$this->assertNull( $rule->inspect( Requests::make( array( 'uri' => '/', 'ip' => '198.51.100.9' ) ) ), 'other IPs unaffected' );
	}

	public function test_ban_expires(): void {
		$rule = $this->rule( array( 'ban_minutes' => 5 ) );
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
		$this->assertNull( $rule->inspect( Requests::make( array( 'uri' => '/.env', 'trusted' => true ) ) ) );
		$this->assertNull( $this->store->get( SensitiveFileRule::ban_key( '203.0.113.10' ) ) );
	}

	public function test_extra_paths(): void {
		$rule = $this->rule( array( 'extra_paths' => array( '/old-admin/' ) ) );
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
}
