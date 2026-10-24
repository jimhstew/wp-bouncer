<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Update;

use PHPUnit\Framework\TestCase;
use WPBouncer\Update\ReleaseManifest;

/**
 * @covers \WPBouncer\Update\ReleaseManifest
 */
final class ReleaseManifestTest extends TestCase {

	private const PREFIX = 'https://github.com/jimhstew/wp-bouncer/releases/download/';

	/** @param array<string, mixed> $override */
	private function json( array $override = array() ): string {
		return (string) json_encode(
			array_merge(
				array(
					'version'      => '1.2.0',
					'package'      => self::PREFIX . 'v1.2.0/wp-bouncer-1.2.0.zip',
					'sha256'       => str_repeat( 'ab', 32 ),
					'requires'     => '5.8',
					'requires_php' => '7.4',
					'tested'       => '7.1',
					'released'     => '2026-10-21',
					'changelog'    => "### Added\n- Updates.",
				),
				$override
			)
		);
	}

	public function test_reads_a_valid_manifest(): void {
		$m = ReleaseManifest::from_json( $this->json(), self::PREFIX );
		$this->assertNotNull( $m );
		$this->assertSame( '1.2.0', $m->version() );
		$this->assertSame( self::PREFIX . 'v1.2.0/wp-bouncer-1.2.0.zip', $m->package() );
		$this->assertSame( str_repeat( 'ab', 32 ), $m->sha256() );
		$this->assertSame( '5.8', $m->requires() );
		$this->assertSame( '7.4', $m->requires_php() );
		$this->assertSame( '7.1', $m->tested() );
		$this->assertSame( '2026-10-21', $m->released() );
	}

	public function test_sha256_is_normalised_to_lowercase(): void {
		$m = ReleaseManifest::from_json( $this->json( array( 'sha256' => str_repeat( 'AB', 32 ) ) ), self::PREFIX );
		$this->assertNotNull( $m );
		$this->assertSame( str_repeat( 'ab', 32 ), $m->sha256() );
	}

	/**
	 * @dataProvider invalid_manifests
	 * @param string $json Manifest.
	 */
	public function test_rejects_invalid_manifests( string $json ): void {
		$this->assertNull( ReleaseManifest::from_json( $json, self::PREFIX ) );
	}

	/** @return array<string, array{0: string}> */
	public function invalid_manifests(): array {
		return array(
			'not json'                   => array( '<html>404</html>' ),
			'json but not an object'     => array( '"1.2.0"' ),
			'no version'                 => array( $this->json( array( 'version' => '' ) ) ),
			'junk version'               => array( $this->json( array( 'version' => 'latest' ) ) ),
			'package from elsewhere'     => array( $this->json( array( 'package' => 'https://evil.example/wp-bouncer-1.2.0.zip' ) ) ),
			'package from another repo'  => array( $this->json( array( 'package' => 'https://github.com/someone/wp-bouncer/releases/download/v1/wp-bouncer.zip' ) ) ),
			'package over http'          => array( $this->json( array( 'package' => 'http://github.com/jimhstew/wp-bouncer/releases/download/v1.2.0/wp-bouncer-1.2.0.zip' ) ) ),
			'package not a zip'          => array( $this->json( array( 'package' => self::PREFIX . 'v1.2.0/wp-bouncer-1.2.0.tar.gz' ) ) ),
			'dot-segment in path'        => array( $this->json( array( 'package' => self::PREFIX . 'v1.2.0/../../../../evil/x/raw/wp-bouncer-1.2.0.zip' ) ) ),
			'encoded dot-segment'        => array( $this->json( array( 'package' => self::PREFIX . 'v1.2.0/%2e%2e/wp-bouncer-1.2.0.zip' ) ) ),
			'tag of a different version' => array( $this->json( array( 'package' => self::PREFIX . 'v1.1.0/wp-bouncer-1.2.0.zip' ) ) ),
			'file of a different version' => array( $this->json( array( 'package' => self::PREFIX . 'v1.2.0/wp-bouncer-1.1.0.zip' ) ) ),
			'query string'               => array( $this->json( array( 'package' => self::PREFIX . 'v1.2.0/wp-bouncer-1.2.0.zip?x=1' ) ) ),
			'extra path segment'         => array( $this->json( array( 'package' => self::PREFIX . 'extra/v1.2.0/wp-bouncer-1.2.0.zip' ) ) ),
			'other file name'            => array( $this->json( array( 'package' => self::PREFIX . 'v1.2.0/other.zip' ) ) ),
			'tag without v'              => array( $this->json( array( 'package' => self::PREFIX . '1.2.0/wp-bouncer-1.2.0.zip' ) ) ),
			'missing sha256'             => array( $this->json( array( 'sha256' => '' ) ) ),
			'short sha256'               => array( $this->json( array( 'sha256' => 'abc123' ) ) ),
			'sha256 not hex'             => array( $this->json( array( 'sha256' => str_repeat( 'zz', 32 ) ) ) ),
			'version is an array'        => array( $this->json( array( 'version' => array( '1.2.0' ) ) ) ),
		);
	}

	public function test_prefix_containing_dot_dot_is_rejected(): void {
		$prefix = 'https://github.com/jimhstew/wp-bouncer/releases/download/../';
		$json   = $this->json( array( 'package' => $prefix . 'v1.2.0/wp-bouncer-1.2.0.zip' ) );
		$this->assertNull( ReleaseManifest::from_json( $json, $prefix ) );
	}

	public function test_expected_package_url_is_exact(): void {
		$this->assertSame( self::PREFIX . 'v3.4.5/wp-bouncer-3.4.5.zip', ReleaseManifest::expected_package( self::PREFIX, '3.4.5' ) );
	}

	public function test_empty_prefix_rejects_everything(): void {
		$this->assertNull( ReleaseManifest::from_json( $this->json(), '' ) );
	}

	public function test_bad_optional_fields_are_dropped_not_fatal(): void {
		$m = ReleaseManifest::from_json(
			$this->json(
				array(
					'requires'     => 'five',
					'requires_php' => '7.4; rm -rf',
					'tested'       => '<b>7</b>',
					'released'     => 'yesterday',
				)
			),
			self::PREFIX
		);
		$this->assertNotNull( $m );
		$this->assertSame( '', $m->requires() );
		$this->assertSame( '', $m->requires_php() );
		$this->assertSame( '', $m->tested() );
		$this->assertSame( '', $m->released() );
	}

	public function test_version_comparison(): void {
		$m = ReleaseManifest::from_json( $this->json(), self::PREFIX );
		$this->assertNotNull( $m );
		$this->assertTrue( $m->is_newer_than( '1.1.0' ) );
		$this->assertTrue( $m->is_newer_than( '1.1.9' ) );
		$this->assertFalse( $m->is_newer_than( '1.2.0' ) );
		$this->assertFalse( $m->is_newer_than( '1.10.0' ), 'numeric, not string, comparison' );
	}

	public function test_prerelease_versions_are_accepted_and_ordered(): void {
		$m = ReleaseManifest::from_json( $this->json( array( 'version' => '1.3.0-beta.1', 'package' => self::PREFIX . 'v1.3.0-beta.1/wp-bouncer-1.3.0-beta.1.zip' ) ), self::PREFIX );
		$this->assertNotNull( $m );
		$this->assertTrue( $m->is_newer_than( '1.2.0' ) );
		$this->assertFalse( $m->is_newer_than( '1.3.0' ) );
	}

	public function test_changelog_html_renders_the_markdown_subset(): void {
		$m = ReleaseManifest::from_json(
			$this->json(
				array(
					'changelog' => "### Fixed\n- Import of a **full** file returned `500`.\n  It now runs in steps.\n- Second item\n\nA closing paragraph.",
				)
			),
			self::PREFIX
		);
		$this->assertNotNull( $m );
		$this->assertSame(
			'<h4>Fixed</h4><ul><li>Import of a <strong>full</strong> file returned <code>500</code>. It now runs in steps.</li><li>Second item</li></ul><p>A closing paragraph.</p>',
			$m->changelog_html()
		);
	}

	public function test_changelog_html_escapes_markup(): void {
		$m = ReleaseManifest::from_json(
			$this->json( array( 'changelog' => "- <script>alert(1)</script>\n<img src=x onerror=alert(1)>" ) ),
			self::PREFIX
		);
		$this->assertNotNull( $m );
		$html = $m->changelog_html();
		$this->assertStringNotContainsString( '<script', $html );
		$this->assertStringNotContainsString( '<img', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
	}

	public function test_long_changelog_is_truncated(): void {
		$m = ReleaseManifest::from_json( $this->json( array( 'changelog' => str_repeat( 'x', 50000 ) ) ), self::PREFIX );
		$this->assertNotNull( $m );
		$this->assertSame( 20000, strlen( $m->changelog() ) );
	}
}
