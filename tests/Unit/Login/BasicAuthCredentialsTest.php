<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Login;

use PHPUnit\Framework\TestCase;
use WPBouncer\Login\BasicAuthEditor;

/**
 * @covers \WPBouncer\Login\BasicAuthEditor::credentials
 */
final class BasicAuthCredentialsTest extends TestCase {

	public function test_php_auth_variables(): void {
		$this->assertSame( array( 'ed', 'abcd efgh' ), BasicAuthEditor::credentials( array( 'PHP_AUTH_USER' => 'ed', 'PHP_AUTH_PW' => 'abcd efgh' ) ) );
	}

	public function test_authorization_headers(): void {
		$b64 = base64_encode( 'ed:pa:ss' );
		$this->assertSame( array( 'ed', 'pa:ss' ), BasicAuthEditor::credentials( array( 'HTTP_AUTHORIZATION' => 'Basic ' . $b64 ) ) );
		$this->assertSame( array( 'ed', 'pa:ss' ), BasicAuthEditor::credentials( array( 'REDIRECT_HTTP_AUTHORIZATION' => 'basic ' . $b64 ) ) );
	}

	public function test_core_precedence_rules(): void {
		$good = 'Basic ' . base64_encode( 'ed:pw' );
		// HTTP_AUTHORIZATION wins over REDIRECT_HTTP_AUTHORIZATION, even if it is malformed (as in core).
		$this->assertNull( BasicAuthEditor::credentials( array( 'HTTP_AUTHORIZATION' => 'Bearer x', 'REDIRECT_HTTP_AUTHORIZATION' => $good ) ) );
		// PHP_AUTH_* set: the header is ignored.
		$this->assertSame( array( 'a', 'b' ), BasicAuthEditor::credentials( array( 'PHP_AUTH_USER' => 'a', 'PHP_AUTH_PW' => 'b', 'HTTP_AUTHORIZATION' => $good ) ) );
		$this->assertNull( BasicAuthEditor::credentials( array( 'PHP_AUTH_PW' => 'b', 'HTTP_AUTHORIZATION' => $good ) ) );
	}

	public function test_no_or_bad_credentials(): void {
		$this->assertNull( BasicAuthEditor::credentials( array() ) );
		$this->assertNull( BasicAuthEditor::credentials( array( 'HTTP_AUTHORIZATION' => 'Bearer abc' ) ) );
		$this->assertNull( BasicAuthEditor::credentials( array( 'HTTP_AUTHORIZATION' => 'Basic !!!' ) ) );
		$this->assertNull( BasicAuthEditor::credentials( array( 'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode( 'nocolon' ) ) ) );
		$this->assertNull( BasicAuthEditor::credentials( array( 'PHP_AUTH_USER' => 'ed' ) ), 'core needs both variables' );
		$this->assertNull( BasicAuthEditor::credentials( array( 'HTTP_AUTHORIZATION' => 'Basic  ' . base64_encode( 'a:b' ) ) ), 'core wants exactly one space' );
	}
}
