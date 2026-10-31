<?php
declare( strict_types=1 );

namespace WPBouncer\Tests\Unit\ThreatMap;

use PHPUnit\Framework\TestCase;
use WPBouncer\Tooling\SvgAllowlist;

require_once dirname( __DIR__, 3 ) . '/scripts/map/SvgAllowlist.php';

/**
 * The generated base map: allowlist, size ceilings and pinned hashes (SB11-11, SB11-12).
 *
 * To regenerate after an intended change: php scripts/build-world-map.php --in <dir>, then update the pins.
 *
 * @covers \WPBouncer\Tooling\SvgAllowlist
 */
final class WorldMapAssetTest extends TestCase {

	private const SVG_SHA256       = '0c6accca693e8cd4bc8d2194d7e936494543ef4164f9584b0b6c54ab6d67310f';
	private const CENTROIDS_SHA256 = '9c73b99eb3eb0af7eea36188e0b52ef11927048d30e9c8c853c8bfdb5c3042a0';

	private function svg_path(): string {
		return dirname( __DIR__, 3 ) . '/wp-bouncer/assets/map/world.svg';
	}

	private function centroids_path(): string {
		return dirname( __DIR__, 3 ) . '/wp-bouncer/src/ThreatMap/Centroids.php';
	}

	public function test_committed_svg_passes_the_allowlist(): void {
		$this->assertSame( array(), SvgAllowlist::check( (string) file_get_contents( $this->svg_path() ) ) );
	}

	public function test_size_ceilings(): void {
		$svg = filesize( $this->svg_path() );
		$this->assertLessThanOrEqual( 85 * 1024, $svg );
		$this->assertLessThanOrEqual( 100 * 1024, $svg + filesize( $this->centroids_path() ) );
	}

	public function test_hashes_are_pinned(): void {
		$this->assertSame( self::SVG_SHA256, hash_file( 'sha256', $this->svg_path() ) );
		$this->assertSame( self::CENTROIDS_SHA256, hash_file( 'sha256', $this->centroids_path() ) );
	}

	public function test_file_has_no_forbidden_text(): void {
		$svg = strtolower( (string) file_get_contents( $this->svg_path() ) );
		foreach ( array( '<script', 'foreignobject', 'href', 'style', 'onload', '<!doctype', '<!--', 'data:', 'javascript' ) as $bad ) {
			$this->assertStringNotContainsString( $bad, $svg, $bad );
		}
	}

	/**
	 * @dataProvider bad_documents
	 */
	public function test_allowlist_rejects( string $svg ): void {
		$this->assertNotSame( array(), SvgAllowlist::check( $svg ) );
	}

	/**
	 * @return array<string,array{string}>
	 */
	public static function bad_documents(): array {
		$o = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" width="10" height="10">';
		return array(
			'script'        => array( $o . '<script>alert(1)</script></svg>' ),
			'foreignObject' => array( $o . '<foreignObject/></svg>' ),
			'onload'        => array( '<svg xmlns="http://www.w3.org/2000/svg" onload="x()"/>' ),
			'href'          => array( $o . '<path d="M0 0z" href="http://x"/></svg>' ),
			'xlink:href'    => array( '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">' . '<path d="M0 0z" xlink:href="#a"/></svg>' ),
			'style attr'    => array( $o . '<path d="M0 0z" style="fill:red"/></svg>' ),
			'style element' => array( $o . '<style>*{}</style></svg>' ),
			'comment'       => array( $o . '<!-- hi --></svg>' ),
			'doctype'       => array( '<!DOCTYPE svg [<!ENTITY a "b">]>' . $o . '</svg>' ),
			'data url'      => array( $o . '<path d="M0 0z" fill="url(data:text/xml,x)"/></svg>' ),
			'bad d'         => array( $o . '<path d="M0 0 url(#x)"/></svg>' ),
			'bad colour'    => array( $o . '<g fill="red"/></svg>' ),
			'pi'            => array( $o . '<?php x ?></svg>' ),
			'not xml'       => array( '<svg' ),
		);
	}
}
