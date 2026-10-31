<?php
namespace WPBouncer\Tests\Unit\ThreatMap;

use PHPUnit\Framework\TestCase;
use WPBouncer\Log\DateRange;
use WPBouncer\ThreatMap\ThreatQuery;

final class ThreatQueryTest extends TestCase {

	private function range( string $from = '', string $to = '' ): DateRange {
		return DateRange::parse( $from, $to, new \DateTimeZone( 'UTC' ), 1793000000 );
	}

	/** @param array<string, string> $f */
	private function q( array $f ): ThreatQuery {
		return ThreatQuery::from_filters( $f, $this->range() );
	}

	/** @dataProvider non_threat_actions */
	public function test_non_threat_actions_are_not_runnable( string $action ): void {
		$q = $this->q( array( 'action' => $action ) );
		$this->assertFalse( $q->runnable() );
		$this->assertSame( 'action', $q->reason() );
	}

	/** @return array<string, array{string}> */
	public static function non_threat_actions(): array {
		return array(
			'login'      => array( 'login' ),
			'alert'      => array( 'alert' ),
			'monitored'  => array( 'monitored' ),
			'suppressed' => array( 'suppressed' ),
			'junk'       => array( 'zzz' ),
		);
	}

	public function test_threat_actions_run(): void {
		foreach ( array( 'blocked', 'lockout', '' ) as $a ) {
			$this->assertTrue( $this->q( array( 'action' => $a ) )->runnable(), $a );
		}
	}

	/** @dataProvider bad_countries */
	public function test_bad_countries_are_not_runnable( string $c ): void {
		$q = $this->q( array( 'country' => $c ) );
		$this->assertFalse( $q->runnable() );
		$this->assertSame( 'country', $q->reason() );
	}

	/** @return array<string, array{string}> */
	public static function bad_countries(): array {
		return array(
			'lt'      => array( '<x' ),
			'quote'   => array( 'a"b' ),
			'digit'   => array( 'us1' ),
			'unknown' => array( 'ZZ' ),
		);
	}

	public function test_country_is_normalised_and_empty_means_any(): void {
		$this->assertSame( array( 'country' => 'DE' ), $this->q( array( 'country' => 'de' ) )->filters() );
		$this->assertTrue( $this->q( array( 'country' => '' ) )->runnable() );
		$this->assertSame( array(), $this->q( array( 'country' => '' ) )->filters() );
	}

	public function test_rule_format_not_label_list(): void {
		$this->assertTrue( $this->q( array( 'rule' => 'my_plugin-rule2' ) )->runnable() );
		foreach ( array( 'Bad Rule', 'a"b', str_repeat( 'a', 33 ), '<x>' ) as $r ) {
			$q = $this->q( array( 'rule' => $r ) );
			$this->assertFalse( $q->runnable(), $r );
			$this->assertSame( 'rule', $q->reason() );
		}
	}

	public function test_search_and_ip_are_dropped(): void {
		$q = $this->q(
			array(
				'search' => 'x',
				'ip'     => '1.2.3.4',
				'rule'   => 'waf',
			)
		);
		$this->assertSame( array( 'rule' => 'waf' ), $q->filters() );
		$this->assertSame( $this->q( array( 'rule' => 'waf' ) )->cache_key( 0 ), $q->cache_key( 0 ) );
	}

	public function test_cache_key_shape_and_sensitivity(): void {
		$a = $this->q( array( 'country' => 'DE' ) );
		$this->assertMatchesRegularExpression( '/^wpb_map_[0-9a-f]{20}$/', $a->cache_key( 3 ) );
		$this->assertLessThan( 60, strlen( $a->cache_key( 3 ) ) );
		$this->assertSame( $a->cache_key( 3 ), $this->q( array( 'country' => 'de' ) )->cache_key( 3 ) );
		$this->assertNotSame( $a->cache_key( 3 ), $a->cache_key( 4 ) );
		$this->assertNotSame( $a->cache_key( 3 ), $this->q( array( 'country' => 'FR' ) )->cache_key( 3 ) );
		$this->assertNotSame(
			$a->cache_key( 3 ),
			$this->q(
				array(
					'country' => 'DE',
					'action'  => 'lockout',
				)
			)->cache_key( 3 )
		);
		$other = ThreatQuery::from_filters( array( 'country' => 'DE' ), $this->range( '2026-10-01', '2026-10-02' ) );
		$this->assertNotSame( $a->cache_key( 3 ), $other->cache_key( 3 ) );
	}
}
