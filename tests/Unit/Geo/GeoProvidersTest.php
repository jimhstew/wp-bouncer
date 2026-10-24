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

	public function test_server_variable_wins_over_a_forged_header_of_the_same_name(): void {
		$geo = new HeaderGeoProvider( array( 'GEOIP_COUNTRY_CODE' => 'DE', 'HTTP_GEOIP_COUNTRY_CODE' => 'US' ), 'GEOIP_COUNTRY_CODE', '1.2.3.4' );
		$this->assertSame( 'DE', $geo->lookup( '1.2.3.4' ) );
	}

	public function test_server_variable_never_falls_back_to_the_http_header(): void {
		$geo = new HeaderGeoProvider( array( 'HTTP_GEOIP_COUNTRY_CODE' => 'US' ), 'GEOIP_COUNTRY_CODE', '1.2.3.4' );
		$this->assertNull( $geo->lookup( '1.2.3.4' ) );
	}

	public function test_untrusted_peer_ignores_a_header_but_not_a_server_variable(): void {
		$header = new HeaderGeoProvider( array( 'HTTP_CF_IPCOUNTRY' => 'DE' ), 'CF-IPCountry', '1.2.3.4', false );
		$this->assertNull( $header->lookup( '1.2.3.4' ) );
		$var = new HeaderGeoProvider( array( 'GEOIP_COUNTRY_CODE' => 'FR' ), 'GEOIP_COUNTRY_CODE', '1.2.3.4', false );
		$this->assertSame( 'FR', $var->lookup( '1.2.3.4' ) );
	}

	public function test_a_forged_http_prefixed_name_is_read_as_a_header_and_gated(): void {
		$server = array( 'HTTP_CF_IPCOUNTRY' => 'US' );
		$this->assertNull( ( new HeaderGeoProvider( $server, 'HTTP_CF_IPCOUNTRY', '1.2.3.4', false ) )->lookup( '1.2.3.4' ) );
		$this->assertSame( 'US', ( new HeaderGeoProvider( $server, 'http_cf_ipcountry', '1.2.3.4', true ) )->lookup( '1.2.3.4' ) );
	}

	public function test_a_mistyped_server_variable_name_is_gated_not_silent(): void {
		$this->assertSame( 'header', HeaderGeoProvider::kind( 'GeoIP_Country_Code' ) );
		$geo = new HeaderGeoProvider( array( 'HTTP_GEOIP_COUNTRY_CODE' => 'US' ), 'GeoIP_Country_Code', '1.2.3.4', false );
		$this->assertNull( $geo->lookup( '1.2.3.4' ) );
	}

	/**
	 * @dataProvider kinds
	 */
	public function test_kind_classifies_names( string $name, string $kind ): void {
		$this->assertSame( $kind, HeaderGeoProvider::kind( $name ) );
	}

	/** @return array<string, array{string, string}> */
	public static function kinds(): array {
		return array(
			'hyphen'          => array( 'CF-IPCountry', 'header' ),
			'known no hyphen' => array( 'cf_ipcountry', 'header' ),
			'cloudfront'      => array( 'CloudFront-Viewer-Country', 'header' ),
			'http prefix'     => array( 'HTTP_CF_IPCOUNTRY', 'header' ),
			'http lower'      => array( 'http_x_geo', 'header' ),
			'mixed case'      => array( 'GeoIP_Country', 'header' ),
			'geoip module'    => array( 'GEOIP_COUNTRY_CODE', 'server_var' ),
			'mm module'       => array( 'MM_COUNTRY_CODE', 'server_var' ),
		);
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
