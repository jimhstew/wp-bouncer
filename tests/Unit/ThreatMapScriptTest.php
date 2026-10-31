<?php
namespace WPBouncer\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class ThreatMapScriptTest extends TestCase {

	public function test_script_avoids_forbidden_apis_and_stays_small(): void {
		$file = dirname( __DIR__, 2 ) . '/wp-bouncer/assets/threat-map.js';
		$js   = (string) file_get_contents( $file );
		foreach ( array( 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'cssText', 'fetch(', 'XMLHttpRequest', 'sendBeacon', 'localStorage.clear', 'jQuery', '.clear()' ) as $token ) {
			$this->assertStringNotContainsString( $token, $js, $token );
		}
		$this->assertLessThanOrEqual( 6000, strlen( $js ) );
		$this->assertStringNotContainsString( 'wpb_map', (string) file_get_contents( dirname( $file ) . '/admin.js' ) );
	}
}
