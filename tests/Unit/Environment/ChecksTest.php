<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Environment;

use PHPUnit\Framework\TestCase;
use WPBouncer\Environment\CheckInterface;
use WPBouncer\Environment\Checks\AutoPrependCheck;
use WPBouncer\Environment\Checks\DatabaseVersionCheck;
use WPBouncer\Environment\Checks\DebugDisplayCheck;
use WPBouncer\Environment\Checks\DebugLogCheck;
use WPBouncer\Environment\Checks\DisableFunctionsCheck;
use WPBouncer\Environment\Checks\ErrorLogLocationCheck;
use WPBouncer\Environment\Checks\FileEditCheck;
use WPBouncer\Environment\Checks\OpenBasedirCheck;
use WPBouncer\Environment\Checks\PhpVersionCheck;
use WPBouncer\Environment\Checks\UploadLimitsCheck;
use WPBouncer\Environment\EnvironmentReport;
use WPBouncer\Environment\Severity;
use WPBouncer\Environment\SupportPolicy;
use WPBouncer\Tests\Support\FakeEnvironment;
use WPBouncer\Tests\Support\FrozenClock;

/**
 * One test per check, against a fake environment.
 *
 * @covers \WPBouncer\Environment\Checks\PhpVersionCheck
 * @covers \WPBouncer\Environment\Checks\DatabaseVersionCheck
 * @covers \WPBouncer\Environment\Checks\IniFlagCheck
 * @covers \WPBouncer\Environment\Checks\ErrorLogLocationCheck
 * @covers \WPBouncer\Environment\Checks\OpenBasedirCheck
 * @covers \WPBouncer\Environment\Checks\DisableFunctionsCheck
 * @covers \WPBouncer\Environment\Checks\AutoPrependCheck
 * @covers \WPBouncer\Environment\Checks\UploadLimitsCheck
 * @covers \WPBouncer\Environment\Checks\FileEditCheck
 * @covers \WPBouncer\Environment\Checks\DebugLogCheck
 * @covers \WPBouncer\Environment\Checks\DebugDisplayCheck
 */
final class ChecksTest extends TestCase {

	/** 2026-10-24 12:00 UTC. */
	private const NOW = 1792843200;

	private function severity( CheckInterface $check, FakeEnvironment $env ): Severity {
		return $check->run( $env )->severity;
	}

	/** Find a built-in check by id. */
	private function builtin( string $id ): CheckInterface {
		foreach ( EnvironmentReport::builtins( new FrozenClock( self::NOW ), new SupportPolicy() ) as $check ) {
			if ( $check->id() === $id ) {
				return $check;
			}
		}
		$this->fail( "No built-in check $id" );
	}

	/* ---------------- versions ---------------- */

	public function test_php_version_states(): void {
		$check = new PhpVersionCheck( new SupportPolicy(), new FrozenClock( self::NOW ) );
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( php: '8.4.1' ) ) );
		$this->assertSame( Severity::Notice, $this->severity( $check, new FakeEnvironment( php: '8.2.20' ) ) );
		$this->assertSame( Severity::Critical, $this->severity( $check, new FakeEnvironment( php: '8.1.30' ) ) );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment( php: '9.9.0' ) ) );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment( php: 'nonsense' ) ) );
		$this->assertSame( 'PHP 8.2', $check->run( new FakeEnvironment( php: '8.2.20' ) )->value );
	}

	public function test_database_version_states(): void {
		$check = new DatabaseVersionCheck( new SupportPolicy(), new FrozenClock( self::NOW ) );
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( db: '10.11.6-MariaDB-log' ) ) );
		$this->assertSame( Severity::Critical, $this->severity( $check, new FakeEnvironment( db: '5.5.5-10.6.18-MariaDB-0ubuntu' ) ) );
		$this->assertSame( Severity::Critical, $this->severity( $check, new FakeEnvironment( db: '8.0.36-0ubuntu' ) ) );
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( db: '8.4.2' ) ) );
		$this->assertSame( Severity::Critical, $this->severity( $check, new FakeEnvironment( db: '9.1.0' ) ), 'an Innovation release that has been replaced' );
		$this->assertSame( Severity::Critical, $this->severity( $check, new FakeEnvironment( db: '5.6.51' ) ) );
		$this->assertSame( Severity::Critical, $this->severity( $check, new FakeEnvironment( db: '10.2.44-MariaDB' ) ) );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment( db: '9.99.0' ) ) );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment( db: '5.7.12 Aurora' ) ) );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment( db: '' ) ) );
		$this->assertSame( 'MariaDB 10.6', $check->run( new FakeEnvironment( db: '10.6.18-MariaDB' ) )->value );
	}

	public function test_a_stale_policy_never_says_supported(): void {
		$late  = (int) strtotime( SupportPolicy::VERIFIED_ON . ' UTC' ) + ( SupportPolicy::STALE_DAYS + 5 ) * 86400;
		$check = new PhpVersionCheck( new SupportPolicy(), new FrozenClock( $late ) );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment( php: '8.5.0' ) ) );
	}

	/* ---------------- php.ini flags ---------------- */

	/**
	 * @dataProvider flag_cases
	 * @param array<string, string> $ini Ini values.
	 */
	public function test_ini_flags( string $id, array $ini, Severity $expected, string $sapi = 'apache2handler', bool $https = true ): void {
		$env = new FakeEnvironment( ini: $ini, sapi: $sapi, https: $https );
		$this->assertSame( $expected, $this->severity( $this->builtin( $id ), $env ), $id . ' ' . json_encode( $ini ) );
	}

	/** @return array<string, array<int, mixed>> */
	public static function flag_cases(): array {
		return array(
			'allow_url_include on'           => array( 'wpb_allow_url_include', array( 'allow_url_include' => '1' ), Severity::Critical ),
			'allow_url_include off'          => array( 'wpb_allow_url_include', array( 'allow_url_include' => '' ), Severity::Ok ),
			'allow_url_include unknown'      => array( 'wpb_allow_url_include', array(), Severity::Unknown ),
			'display_errors on'              => array( 'wpb_display_errors', array( 'display_errors' => 'On' ), Severity::Warning ),
			'display_errors stdout'          => array( 'wpb_display_errors', array( 'display_errors' => 'stdout' ), Severity::Warning ),
			'display_errors off'             => array( 'wpb_display_errors', array( 'display_errors' => 'Off' ), Severity::Ok ),
			'display_errors odd'             => array( 'wpb_display_errors', array( 'display_errors' => 'maybe' ), Severity::Unknown ),
			'startup errors with display'    => array(
				'wpb_display_startup_errors',
				array(
					'display_startup_errors' => '1',
					'display_errors'         => '1',
				),
				Severity::Warning,
			),
			'startup errors without'         => array(
				'wpb_display_startup_errors',
				array(
					'display_startup_errors' => '1',
					'display_errors'         => '0',
				),
				Severity::Info,
			),
			'startup errors off'             => array(
				'wpb_display_startup_errors',
				array(
					'display_startup_errors' => '0',
					'display_errors'         => '1',
				),
				Severity::Ok,
			),
			'log_errors off'                 => array( 'wpb_log_errors', array( 'log_errors' => '0' ), Severity::Info ),
			'log_errors on'                  => array( 'wpb_log_errors', array( 'log_errors' => '1' ), Severity::Ok ),
			'expose_php on'                  => array( 'wpb_expose_php', array( 'expose_php' => '1' ), Severity::Info ),
			'allow_url_fopen on'             => array( 'wpb_allow_url_fopen', array( 'allow_url_fopen' => '1' ), Severity::Info ),
			'strict mode off'                => array( 'wpb_session_strict_mode', array( 'session.use_strict_mode' => '0' ), Severity::Info ),
			'only cookies off'               => array( 'wpb_session_only_cookies', array( 'session.use_only_cookies' => '0' ), Severity::Info ),
			'trans sid on'                   => array( 'wpb_session_trans_sid', array( 'session.use_trans_sid' => '1' ), Severity::Info ),
			'httponly off'                   => array( 'wpb_session_httponly', array( 'session.cookie_httponly' => '0' ), Severity::Info ),
			'secure cookie off on https'     => array( 'wpb_session_secure', array( 'session.cookie_secure' => '0' ), Severity::Info, 'apache2handler', true ),
			'secure cookie off on http'      => array( 'wpb_session_secure', array( 'session.cookie_secure' => '0' ), Severity::Ok, 'apache2handler', false ),
			'assertions on'                  => array( 'wpb_zend_assertions', array( 'zend.assertions' => '1' ), Severity::Info ),
			'assertions off (-1)'            => array( 'wpb_zend_assertions', array( 'zend.assertions' => '-1' ), Severity::Ok ),
			'fix_pathinfo on, fpm'           => array( 'wpb_cgi_fix_pathinfo', array( 'cgi.fix_pathinfo' => '1' ), Severity::Info, 'fpm-fcgi' ),
			'fix_pathinfo on, apache module' => array( 'wpb_cgi_fix_pathinfo', array( 'cgi.fix_pathinfo' => '1' ), Severity::Ok, 'apache2handler' ),
			'fix_pathinfo off, cgi'          => array( 'wpb_cgi_fix_pathinfo', array( 'cgi.fix_pathinfo' => '0' ), Severity::Ok, 'cgi-fcgi' ),
		);
	}

	/* ---------------- path and list checks ---------------- */

	public function test_error_log_location_never_shows_the_path(): void {
		$check = new ErrorLogLocationCheck();
		$env   = new FakeEnvironment( ini: array( 'error_log' => '/var/www/html/wp-content/php.log' ), inside: array( '/var/www/html/wp-content/php.log' => true ) );
		$r     = $check->run( $env );
		$this->assertSame( Severity::Warning, $r->severity );
		$this->assertTrue( $r->is_private );
		$this->assertStringNotContainsString( '/var/www', $r->value );

		$out = new FakeEnvironment( ini: array( 'error_log' => '/var/log/php.log' ), inside: array( '/var/log/php.log' => false ) );
		$this->assertSame( Severity::Ok, $this->severity( $check, $out ) );
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( ini: array( 'error_log' => '' ) ) ) );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment( ini: array( 'error_log' => '/odd' ) ) ), 'cannot tell where it is' );
	}

	public function test_error_log_syslog_is_fine_and_relative_paths_are_unknown(): void {
		$check = new ErrorLogLocationCheck();
		foreach ( array( 'syslog', 'SysLog', ' syslog ' ) as $value ) {
			$r = $check->run( new FakeEnvironment( ini: array( 'error_log' => $value ) ) );
			$this->assertSame( Severity::Ok, $r->severity, $value );
			$this->assertSame( 'Sent to the system log', $r->value );
		}
		foreach ( array( 'php_errors.log', './logs/php.log', '../php.log', 'logs/php.log' ) as $value ) {
			$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment( ini: array( 'error_log' => $value ), inside: array( $value => true ) ) ), $value );
		}
		foreach ( array( '/var/log/php.log', 'C:\\logs\\php.log', 'D:/logs/php.log', '\\\\server\\share\\php.log' ) as $value ) {
			$this->assertSame( Severity::Warning, $this->severity( $check, new FakeEnvironment( ini: array( 'error_log' => $value ), inside: array( $value => true ) ) ), $value . ' is absolute' );
		}
	}

	public function test_open_basedir_shows_only_a_count(): void {
		$check = new OpenBasedirCheck();
		$r     = $check->run( new FakeEnvironment( ini: array( 'open_basedir' => '/srv/a:/srv/b:/tmp' ) ) );
		$this->assertSame( Severity::Ok, $r->severity );
		$this->assertSame( 'Set (3 paths)', $r->value );
		$this->assertTrue( $r->is_private );
		$this->assertSame( Severity::Info, $this->severity( $check, new FakeEnvironment( ini: array( 'open_basedir' => '' ) ) ) );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment() ) );
	}

	public function test_disable_functions_lists_only_the_missing_names(): void {
		$check = new DisableFunctionsCheck();
		$r     = $check->run( new FakeEnvironment( ini: array( 'disable_functions' => 'exec,passthru, shell_exec ,mail,curl_exec' ) ) );
		$this->assertSame( Severity::Info, $r->severity );
		$this->assertSame( 'Not disabled: system, proc_open, popen', $r->value );
		$this->assertStringNotContainsString( 'mail', $r->value );
		$all = $check->run( new FakeEnvironment( ini: array( 'disable_functions' => 'exec,passthru,shell_exec,system,proc_open,popen' ) ) );
		$this->assertSame( Severity::Ok, $all->severity );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment() ) );
	}

	public function test_auto_prepend_says_only_set_or_not_set(): void {
		$check = new AutoPrependCheck();
		$r     = $check->run(
			new FakeEnvironment(
				ini: array(
					'auto_prepend_file' => '/opt/waf/prepend.php',
					'auto_append_file'  => '',
				)
			)
		);
		$this->assertSame( Severity::Info, $r->severity );
		$this->assertStringNotContainsString( '/opt', $r->value );
		$this->assertTrue( $r->is_private );
		$this->assertSame(
			Severity::Ok,
			$this->severity(
				$check,
				new FakeEnvironment(
					ini: array(
						'auto_prepend_file' => '',
						'auto_append_file'  => '',
					)
				)
			)
		);
	}

	public function test_upload_limits_are_context_only(): void {
		$check = new UploadLimitsCheck();
		$r     = $check->run(
			new FakeEnvironment(
				ini: array(
					'file_uploads'        => '1',
					'upload_max_filesize' => '64M',
					'post_max_size'       => '128M',
					'max_input_vars'      => '3000',
				)
			)
		);
		$this->assertSame( Severity::Info, $r->severity );
		$this->assertStringContainsString( 'max_input_vars: 3000', $r->value );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment() ) );
		$unlimited = $check->run(
			new FakeEnvironment(
				ini: array(
					'file_uploads'        => '1',
					'upload_max_filesize' => '0',
					'post_max_size'       => '-1',
					'max_input_vars'      => '1000',
				)
			)
		);
		$this->assertStringContainsString( 'upload_max_filesize: unlimited', $unlimited->value );
		$this->assertStringContainsString( 'post_max_size: unlimited', $unlimited->value );
	}

	/* ---------------- WordPress ---------------- */

	public function test_file_edit(): void {
		$check = new FileEditCheck();
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( constants: array( 'DISALLOW_FILE_EDIT' => 1 ) ) ), 'truthy, as in core' );
		$this->assertSame( Severity::Warning, $this->severity( $check, new FakeEnvironment() ) );
		$this->assertSame( Severity::Warning, $this->severity( $check, new FakeEnvironment( constants: array( 'DISALLOW_FILE_EDIT' => false ) ) ) );
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( constants: array( 'DISALLOW_FILE_EDIT' => true ) ) ) );
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( constants: array( 'DISALLOW_FILE_MODS' => true ) ) ), 'file mods off also stops the editor' );
	}

	public function test_debug_log(): void {
		$check = new DebugLogCheck();
		$base  = array(
			'WP_DEBUG'       => true,
			'WP_CONTENT_DIR' => '/var/www/html/wp-content',
		);
		$log   = '/var/www/html/wp-content/debug.log';
		$this->assertSame(
			Severity::Ok,
			$this->severity(
				$check,
				new FakeEnvironment(
					constants: array(
						'WP_DEBUG'       => false,
						'WP_DEBUG_LOG'   => true,
						'WP_CONTENT_DIR' => '/x',
					)
				)
			),
			'debug off'
		);
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( constants: $base + array( 'WP_DEBUG_LOG' => false ) ) ) );
		$this->assertSame( Severity::Warning, $this->severity( $check, new FakeEnvironment( constants: $base + array( 'WP_DEBUG_LOG' => true ), inside: array( $log => true ) ) ), 'default debug.log' );
		$this->assertSame( Severity::Warning, $this->severity( $check, new FakeEnvironment( constants: $base + array( 'WP_DEBUG_LOG' => 'true' ), inside: array( $log => true ) ) ), 'the string "true" means the default file' );
		$this->assertSame( Severity::Warning, $this->severity( $check, new FakeEnvironment( constants: $base + array( 'WP_DEBUG_LOG' => 1 ), inside: array( $log => true ) ) ), 'truthy, as in core' );
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( constants: $base + array( 'WP_DEBUG_LOG' => true ), inside: array( $log => false ) ) ), 'content dir outside the WordPress folder' );
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( constants: $base + array( 'WP_DEBUG_LOG' => '/var/log/wp.log' ), inside: array( '/var/log/wp.log' => false ) ) ) );
		$this->assertSame( Severity::Warning, $this->severity( $check, new FakeEnvironment( constants: $base + array( 'WP_DEBUG_LOG' => '/var/www/html/logs/wp.log' ), inside: array( '/var/www/html/logs/wp.log' => true ) ) ) );
		$this->assertSame( Severity::Unknown, $this->severity( $check, new FakeEnvironment( constants: $base + array( 'WP_DEBUG_LOG' => true ) ) ) );
		$r = $check->run( new FakeEnvironment( constants: $base + array( 'WP_DEBUG_LOG' => true ), inside: array( $log => true ) ) );
		$this->assertStringNotContainsString( '/var/www', $r->value );
		$this->assertTrue( $r->is_private );
	}

	public function test_debug_log_warns_about_an_old_log_left_behind(): void {
		$check = new DebugLogCheck();
		$dir   = '/var/www/html/wp-content';
		$old   = $dir . '/debug.log';
		$base  = array(
			'WP_DEBUG'       => false,
			'WP_CONTENT_DIR' => $dir,
		);
		$left  = new FakeEnvironment( constants: $base, inside: array( $dir => true ), files: array( $old => 5120 ) );
		$this->assertSame( Severity::Warning, $this->severity( $check, $left ) );
		$this->assertStringNotContainsString( '/var/www', $check->run( $left )->value );

		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( constants: $base, inside: array( $dir => true ), files: array( $old => 0 ) ) ), 'empty' );
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( constants: $base, inside: array( $dir => true ) ) ), 'no file' );
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment( constants: $base, inside: array( $dir => false ), files: array( $old => 5120 ) ) ), 'outside the WordPress folder' );
	}

	public function test_debug_display_is_dashboard_only(): void {
		$check = new DebugDisplayCheck();
		$this->assertTrue( $check->run( new FakeEnvironment() )->dashboard_only );
		$this->assertSame( Severity::Warning, $this->severity( $check, new FakeEnvironment( constants: array( 'WP_DEBUG' => true ) ) ), 'the default is to display' );
		$this->assertSame(
			Severity::Warning,
			$this->severity(
				$check,
				new FakeEnvironment(
					constants: array(
						'WP_DEBUG'         => 1,
						'WP_DEBUG_DISPLAY' => 1,
					)
				)
			),
			'truthy, as in core'
		);
		$this->assertSame(
			Severity::Ok,
			$this->severity(
				$check,
				new FakeEnvironment(
					constants: array(
						'WP_DEBUG'         => true,
						'WP_DEBUG_DISPLAY' => 0,
					)
				)
			)
		);
		$this->assertSame(
			Severity::Warning,
			$this->severity(
				$check,
				new FakeEnvironment(
					constants: array(
						'WP_DEBUG'         => true,
						'WP_DEBUG_DISPLAY' => true,
					)
				)
			)
		);
		$this->assertSame(
			Severity::Ok,
			$this->severity(
				$check,
				new FakeEnvironment(
					constants: array(
						'WP_DEBUG'         => true,
						'WP_DEBUG_DISPLAY' => false,
					)
				)
			)
		);
		$this->assertSame( Severity::Ok, $this->severity( $check, new FakeEnvironment() ), 'WP_DEBUG off' );
	}

	public function test_force_ssl_admin_is_not_checked(): void {
		foreach ( EnvironmentReport::builtins( new FrozenClock( self::NOW ), new SupportPolicy() ) as $check ) {
			$this->assertStringNotContainsString( 'ssl', $check->id() );
		}
	}
}
