<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\AdminLogins;

use PHPUnit\Framework\TestCase;
use WPBouncer\AdminLogins\LocationHistory;
use WPBouncer\AdminLogins\LoginAssessment;
use WPBouncer\AdminLogins\LoginLocationPolicy;

/**
 * @covers \WPBouncer\AdminLogins\LoginLocationPolicy
 * @covers \WPBouncer\AdminLogins\LoginAssessment
 */
final class LoginLocationPolicyTest extends TestCase {

	private const NOW    = 1800000000;
	private const WINDOW = 90 * 86400;

	private function policy(): LoginLocationPolicy {
		return new LoginLocationPolicy( self::WINDOW, 20 );
	}

	/** @param array<int, array{0:string,1:string,2:int}> $logins range, country, time. */
	private function history( int $since, array $logins ): LocationHistory {
		$h = LocationHistory::start( $since );
		foreach ( $logins as $l ) {
			$h = $h->with_login( $l[0], $l[1], $l[2], self::WINDOW, 20 );
		}
		return $h;
	}

	/** @dataProvider ranges */
	public function test_range_of( string $ip, string $range ): void {
		$this->assertSame( $range, LoginLocationPolicy::range_of( $ip ) );
	}

	public static function ranges(): array {
		return array(
			'ipv4'            => array( '203.0.113.77', '203.0.113.0/24' ),
			'ipv6 compressed' => array( '2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64' ),
			'ipv6 full'       => array( '2001:0db8:0001:0002:0003:0004:0005:0006', '2001:db8:1:2::/64' ),
			'ipv6 short'      => array( '2001:db8::1', '2001:db8::/64' ),
			'mapped ipv4'     => array( '::ffff:203.0.113.77', '203.0.113.0/24' ),
			'junk'            => array( 'not an ip', '' ),
			'empty'           => array( '', '' ),
			'bad octet'       => array( '300.1.1.1', '' ),
		);
	}

	public function test_first_login_is_silent_and_starts_the_history(): void {
		$a = $this->policy()->assess( null, '203.0.113.0/24', 'DE', self::NOW );
		$this->assertTrue( $a->first );
		$this->assertFalse( $a->is_new_location() );
		$this->assertSame( self::NOW, $a->history->since() );
		$this->assertTrue( $a->history->has_range( '203.0.113.0/24' ) );
		$this->assertSame( array( 'DE' ), $a->history->known_countries() );
	}

	public function test_same_range_does_not_alert_and_refreshes_the_time(): void {
		$h = $this->history( self::NOW - 1000, array( array( '203.0.113.0/24', 'DE', self::NOW - 1000 ) ) );
		$a = $this->policy()->assess( $h, '203.0.113.0/24', 'DE', self::NOW );
		$this->assertFalse( $a->first );
		$this->assertFalse( $a->is_new_location() );
		$this->assertSame( self::NOW, $a->history->entries()[0]['t'] );
	}

	public function test_new_range_in_a_known_country_alerts(): void {
		$h = $this->history( self::NOW - 1000, array( array( '203.0.113.0/24', 'DE', self::NOW - 1000 ) ) );
		$a = $this->policy()->assess( $h, '198.51.100.0/24', 'DE', self::NOW );
		$this->assertTrue( $a->new_range );
		$this->assertFalse( $a->new_country );
		$this->assertTrue( $a->is_new_location() );
		$this->assertTrue( $a->history->has_range( '198.51.100.0/24' ) );
		$this->assertTrue( $a->history->has_range( '203.0.113.0/24' ) );
	}

	public function test_new_country_with_a_known_range_alerts(): void {
		$h = $this->history( self::NOW - 1000, array( array( '203.0.113.0/24', 'DE', self::NOW - 1000 ) ) );
		$a = $this->policy()->assess( $h, '203.0.113.0/24', 'FR', self::NOW );
		$this->assertFalse( $a->new_range );
		$this->assertTrue( $a->new_country );
		$this->assertTrue( $a->is_new_location() );
	}

	public function test_no_geo_data_the_range_alone_decides(): void {
		$h = $this->history( self::NOW - 1000, array( array( '203.0.113.0/24', 'DE', self::NOW - 1000 ) ) );
		$same = $this->policy()->assess( $h, '203.0.113.0/24', '', self::NOW );
		$this->assertFalse( $same->is_new_location(), 'an empty country is never new' );
		$this->assertSame( 'DE', $same->history->entries()[0]['c'], 'an empty country does not erase a known one' );
		$new = $this->policy()->assess( $h, '198.51.100.0/24', '', self::NOW );
		$this->assertTrue( $new->is_new_location() );
		$this->assertFalse( $new->new_country );
	}

	public function test_a_country_is_learned_silently_when_the_history_has_none(): void {
		$h = $this->history( self::NOW - 1000, array( array( '203.0.113.0/24', '', self::NOW - 1000 ) ) );
		$a = $this->policy()->assess( $h, '203.0.113.0/24', 'DE', self::NOW );
		$this->assertFalse( $a->is_new_location() );
		$this->assertSame( array( 'DE' ), $a->history->known_countries() );
	}

	public function test_expired_history_is_not_first_and_alerts(): void {
		$old = self::NOW - self::WINDOW - 10;
		$h   = $this->history( $old - 5000, array( array( '203.0.113.0/24', 'DE', $old ) ) );
		$a   = $this->policy()->assess( $h, '203.0.113.0/24', 'DE', self::NOW );
		$this->assertFalse( $a->first, 'a dormant account is not a first login' );
		$this->assertTrue( $a->new_range );
		$this->assertTrue( $a->is_new_location() );
		$this->assertSame( $old - 5000, $a->history->since(), 'since survives pruning' );
		$this->assertCount( 1, $a->history->entries() );
	}

	public function test_window_boundary(): void {
		$h = $this->history( 1, array( array( '203.0.113.0/24', 'DE', self::NOW - self::WINDOW ) ) );
		$this->assertFalse( $this->policy()->assess( $h, '203.0.113.0/24', 'DE', self::NOW )->new_range, 'exactly at the cut-off is kept' );
		$this->assertTrue( $this->policy()->assess( $h, '203.0.113.0/24', 'DE', self::NOW + 1 )->new_range, 'one second older is gone' );
	}

	public function test_the_history_is_capped_at_20_and_the_oldest_drop(): void {
		$h = LocationHistory::start( self::NOW - 100000 );
		for ( $i = 1; $i <= 25; $i++ ) {
			$h = $this->policy()->assess( $h, '10.0.' . $i . '.0/24', 'DE', self::NOW - 1000 + $i )->history;
		}
		$this->assertCount( 20, $h->entries() );
		$this->assertFalse( $h->has_range( '10.0.1.0/24' ) );
		$this->assertFalse( $h->has_range( '10.0.5.0/24' ) );
		$this->assertTrue( $h->has_range( '10.0.6.0/24' ) );
		$this->assertTrue( $h->has_range( '10.0.25.0/24' ) );
	}

	public function test_an_unusable_range_is_never_new_and_is_not_stored(): void {
		$h = $this->history( self::NOW - 1000, array( array( '203.0.113.0/24', 'DE', self::NOW - 1000 ) ) );
		$a = $this->policy()->assess( $h, '', '', self::NOW );
		$this->assertFalse( $a->is_new_location() );
		$this->assertCount( 1, $a->history->entries() );
	}
}
