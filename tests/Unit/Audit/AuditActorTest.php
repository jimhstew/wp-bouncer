<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Audit;

use PHPUnit\Framework\TestCase;
use WPBouncer\Audit\AuditActor;

/**
 * @covers \WPBouncer\Audit\AuditActor
 */
final class AuditActorTest extends TestCase {

	public function test_a_login_alone_is_the_actor(): void {
		$this->assertSame( 'jim', AuditActor::resolve( 'jim', array() ) );
	}

	public function test_neither_login_nor_context_is_unknown(): void {
		$this->assertSame( 'unknown', AuditActor::resolve( null, array() ) );
		$this->assertSame( 'unknown', AuditActor::resolve( '', array( 'cli' => false ) ) );
	}

	/** @return array<string, array{0: string}> */
	public static function labels(): array {
		return array(
			'upgrade' => array( 'upgrade' ),
			'cli'     => array( 'cli' ),
			'cron'    => array( 'cron' ),
			'rest'    => array( 'rest' ),
			'ajax'    => array( 'ajax' ),
		);
	}

	/** @dataProvider labels */
	public function test_a_label_alone_and_with_a_login( string $label ): void {
		$this->assertSame( $label, AuditActor::resolve( null, array( $label => true ) ) );
		$this->assertSame( "jim ($label)", AuditActor::resolve( 'jim', array( $label => true ) ) );
	}

	public function test_the_first_flag_in_priority_order_wins(): void {
		$all = array(
			'ajax'    => true,
			'rest'    => true,
			'cron'    => true,
			'cli'     => true,
			'upgrade' => true,
		);
		$this->assertSame( 'upgrade', AuditActor::resolve( null, $all ) );
		unset( $all['upgrade'] );
		$this->assertSame( 'jim (cli)', AuditActor::resolve( 'jim', $all ) );
		unset( $all['cli'] );
		$this->assertSame( 'cron', AuditActor::resolve( null, $all ) );
		unset( $all['cron'] );
		$this->assertSame( 'rest', AuditActor::resolve( null, $all ) );
	}

	public function test_control_characters_are_stripped(): void {
		$this->assertSame( 'jimevil', AuditActor::resolve( "jim\r\n\x00evil\x1b", array() ) );
		$this->assertSame( 'unknown', AuditActor::resolve( "\r\n\t", array() ) );
	}

	public function test_a_long_login_is_capped_at_60_characters(): void {
		$this->assertSame( str_repeat( 'a', 60 ), AuditActor::resolve( str_repeat( 'a', 200 ), array() ) );
	}

	public function test_the_user_id_follows_the_login(): void {
		$this->assertSame( 'jim #7', AuditActor::resolve( 'jim', array(), 7 ) );
		$this->assertSame( 'jim #7 (cli)', AuditActor::resolve( 'jim', array( 'cli' => true ), 7 ) );
		$this->assertSame( 'cli', AuditActor::resolve( null, array( 'cli' => true ), 7 ) );
	}

	public function test_format_and_c1_characters_are_stripped(): void {
		$this->assertSame( 'jim', AuditActor::resolve( "j\u{200B}i\u{202E}m\u{0085}", array() ) );
		$this->assertSame( 'unknown', AuditActor::resolve( "\u{200B}\u{202E}", array() ) );
	}

	public function test_the_id_stays_when_the_login_strips_to_nothing(): void {
		$this->assertSame( '#7', AuditActor::resolve( "\u{200B}", array(), 7 ) );
		$this->assertSame( '#7 (cli)', AuditActor::resolve( "\u{200B}", array( 'cli' => true ), 7 ) );
	}
}
