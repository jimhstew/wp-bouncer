<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Geo;

use PHPUnit\Framework\TestCase;
use WPBouncer\Geo\ChainGeoProvider;
use WPBouncer\Geo\HeaderGeoProvider;
use WPBouncer\Tests\Support\FakeGeo;

/**
 * @covers \WPBouncer\Geo\HeaderGeoProvider
 * @covers \WPBouncer\Geo\ChainGeoProvider
 */
final class GeoProvidersTest extends TestCase {

	public function test_header_provider_reads_http_header(): void {
		$geo = new HeaderGeoProvider( array( 'HTTP_CF_IPCOUNTRY' => 'de' ), 'CF-IPCountry', '1.2.3.4' );
		$this->assertSame( 'DE', $geo->lookup( '1.2.3.4' ) );
	}

	public function test_header_provider_reads_server_variable(): void {
		$geo = new HeaderGeoProvider( array( 'GEOIP_COUNTRY_CODE' => 'FR' ), 'GEOIP_COUNTRY_CODE', '1.2.3.4' );
		$this->assertSame( 'FR', $geo->lookup( '1.2.3.4' ) );
	}

	public function test_header_provider_only_answers_for_the_current_request(): void {
		$geo = new HeaderGeoProvider( array( 'HTTP_CF_IPCOUNTRY' => 'DE' ), 'CF-IPCountry', '1.2.3.4' );
		$this->assertNull( $geo->lookup( '5.6.7.8' ) );
	}

	public function test_header_provider_rejects_placeholders_and_junk(): void {
		foreach ( array( 'XX', '', 'Germany', '1', 'D' ) as $value ) {
			$geo = new HeaderGeoProvider( array( 'HTTP_CF_IPCOUNTRY' => $value ), 'CF-IPCountry', '1.2.3.4' );
			$this->assertNull( $geo->lookup( '1.2.3.4' ), var_export( $value, true ) );
		}
		$tor = new HeaderGeoProvider( array( 'HTTP_CF_IPCOUNTRY' => 'T1' ), 'CF-IPCountry', '1.2.3.4' );
		$this->assertSame( 'T1', $tor->lookup( '1.2.3.4' ) );
	}

	public function test_chain_returns_first_answer_and_caches(): void {
		$first  = new FakeGeo( array() );
		$second = new FakeGeo( array( '1.2.3.4' => 'NL' ) );
		$chain  = new ChainGeoProvider( array( $first, $second ) );

		$this->assertSame( 'NL', $chain->lookup( '1.2.3.4' ) );
		$this->assertSame( 'NL', $chain->lookup( '1.2.3.4' ) );
		$this->assertSame( 1, $first->lookups );
		$this->assertSame( 1, $second->lookups, 'second call served from cache' );

		$this->assertNull( $chain->lookup( '9.9.9.9' ) );
		$this->assertNull( ( new ChainGeoProvider( array() ) )->lookup( '1.2.3.4' ) );
	}
}
