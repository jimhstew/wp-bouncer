<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\AdminLogins;

use PHPUnit\Framework\TestCase;
use WPBouncer\AdminLogins\LocationHistory;
use WPBouncer\AdminLogins\LoginAssessment;
use WPBouncer\AdminLogins\LoginEvent;

/**
 * @covers \WPBouncer\AdminLogins\LoginEvent
 */
final class LoginEventTest extends TestCase {

	private function event( int $id = 12, string $login = 'jim', string $method = LoginEvent::METHOD_INTERACTIVE ): LoginEvent {
		return new LoginEvent( $id, $login, '203.0.113.9', '203.0.113.0/24', 'DE', $method, 1800000000 );
	}

	public function test_prefix_of_id_1_does_not_match_id_12(): void {
		$reason = $this->event( 12 )->reason();
		$this->assertStringStartsWith( 'User ID 12: jim', $reason );
		$this->assertStringStartsNotWith( LoginEvent::reason_prefix( 1 ), $reason );
		$this->assertStringStartsWith( LoginEvent::reason_prefix( 12 ), $reason );
		$this->assertSame( 'User ID 1:', LoginEvent::reason_prefix( 1 ) );
	}

	public function test_a_hostile_login_name_cannot_forge_another_users_prefix(): void {
		$reason = $this->event( 7, "User ID 5: x\nUser ID 5:" )->reason();
		$this->assertStringStartsWith( 'User ID 7:', $reason );
		$this->assertStringStartsNotWith( LoginEvent::reason_prefix( 5 ), $reason );
		$this->assertStringNotContainsString( "\n", $reason );
	}

	public function test_control_characters_are_stripped_and_the_login_is_capped(): void {
		$e = $this->event( 3, "a\x00b\x1b[31m\r\nc" . str_repeat( 'z', 100 ) );
		$this->assertDoesNotMatchRegularExpression( '/[\x00-\x1F\x7F]/', $e->login );
		$this->assertSame( 60, mb_strlen( $e->login ) );
		$this->assertDoesNotMatchRegularExpression( '/[\x00-\x1F\x7F]/', $e->reason() );
	}

	public function test_bidi_and_zero_width_format_characters_are_stripped_from_the_login(): void {
		// U+202E right-to-left override, U+200B zero-width space, U+0085 next line (C1), U+FEFF BOM.
		$e = $this->event( 3, "ad\u{202E}min\u{200B}\u{85}x\u{FEFF}" );
		$this->assertDoesNotMatchRegularExpression( '/[\p{Cc}\p{Cf}]/u', $e->login );
		$this->assertDoesNotMatchRegularExpression( '/[\p{Cc}\p{Cf}]/u', $e->reason() );
		$this->assertSame( 'ad min x', $e->login );
	}

	public function test_an_invalid_utf8_login_does_not_break_the_event(): void {
		$e = $this->event( 3, "bad\xFF\xFEname" );
		$this->assertSame( '', $e->login );
	}

	public function test_markup_is_kept_as_text_for_output_escaping(): void {
		$e = $this->event( 3, '<b>x</b>' );
		$this->assertSame( '<b>x</b>', $e->login );
	}

	public function test_reason_is_at_most_255_chars_and_keeps_the_prefix(): void {
		$reason = $this->event( 12 )->reason( str_repeat( 'n', 400 ) );
		$this->assertSame( 255, mb_strlen( $reason ) );
		$this->assertStringStartsWith( 'User ID 12: jim', $reason );
	}

	/** @dataProvider methods */
	public function test_every_method_label( string $method ): void {
		$this->assertStringContainsString( ' — ' . $method, $this->event( 12, 'jim', $method )->reason() );
		$this->assertContains( $method, LoginEvent::methods() );
	}

	public static function methods(): array {
		return array(
			array( 'interactive password' ),
			array( 'interactive password + two-factor' ),
			array( 'application password (REST)' ),
			array( 'application password (XML-RPC)' ),
			array( 'password (XML-RPC)' ),
		);
	}

	public function test_an_unknown_method_throws(): void {
		$this->expectException( \InvalidArgumentException::class );
		$this->event( 12, 'jim', 'magic link' );
	}

	public function test_reason_formats_from_the_design(): void {
		$this->assertSame( 'User ID 12: jim — interactive password', $this->event()->reason() );
		$this->assertSame(
			'User ID 12: jim — interactive password — first recorded login, location history started',
			$this->event()->reason( 'first recorded login, location history started' )
		);
	}

	public function test_email_detail_names_the_user_and_what_is_new_and_nothing_secret(): void {
		$a      = new LoginAssessment( false, true, true, LocationHistory::start( 1 ) );
		$detail = $this->event( 12, 'jim', LoginEvent::METHOD_APP_REST )->email_detail( $a );
		$this->assertSame( 'User: jim (user ID 12). Method: application password (REST). New: IP range 203.0.113.0/24, country DE.', $detail );
		$this->assertStringNotContainsString( '@', $detail );
		$only_country = new LoginAssessment( false, false, true, LocationHistory::start( 1 ) );
		$this->assertStringContainsString( 'New: country DE.', $this->event()->email_detail( $only_country ) );
	}

	public function test_to_array_shape(): void {
		$this->assertSame(
			array( 'user_id', 'login', 'ip', 'range', 'country', 'method', 'time' ),
			array_keys( $this->event()->to_array() )
		);
	}
}
