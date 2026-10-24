<?php
/**
 * The requirements guard in wp-bouncer.php, run in a child PHP process
 * (the file defines constants and returns early, so it can't be included twice).
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class MainFileGuardTest extends TestCase {

	/**
	 * @return array<string, mixed>
	 */
	private function run_with( string $wp_version ): array {
		$cmd = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( dirname( __DIR__ ) . '/fixtures/guard-runner.php' ) . ' ' . escapeshellarg( $wp_version ) . ' 2>&1';
		$out = (string) shell_exec( $cmd );
		$this->assertJson( $out, $out );
		return json_decode( $out, true );
	}

	public function test_an_old_wordpress_shows_a_notice_and_does_not_boot(): void {
		$r = $this->run_with( '6.9' );
		$this->assertFalse( $r['booted'] );
		$this->assertContains( 'admin_notices', $r['hooks'] );
		$this->assertNotContains( 'booted', $r['hooks'] );
		$this->assertStringContainsString( 'WP Bouncer is not running', $r['notice'] );
	}

	public function test_a_release_candidate_of_the_minimum_boots(): void {
		$r = $this->run_with( '7.0-RC1' );
		$this->assertNotContains( 'admin_notices', $r['hooks'] );
		$this->assertTrue( $r['booted'], 'the guard let it through to Plugin' );
	}
}
