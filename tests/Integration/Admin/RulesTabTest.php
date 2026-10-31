<?php
/**
 * The Rules tab in categories (WPB-2): markup, deep links, status, third-party rows, the
 * Dashboard overview, and above all the round trip that guards against silent switch-offs.
 *
 * The round-trip tests run on single site and on multisite (WP_MULTISITE=1), as a site
 * administrator and as a network administrator. On a single site both are the same person.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\RuleCatalog;
use WPBouncer\Admin\RuleLabels;
use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Plugin;
use WPBouncer\Rules\AbstractRule;
use WPBouncer\Rules\RuleInterface;
use WPBouncer\Settings;
use WPBouncer\Tests\Integration\IntegrationTestCase;
use WPBouncer\Tests\Support\FormFields;

/**
 * @covers \WPBouncer\Admin\AdminController
 * @covers \WPBouncer\Admin\RuleOverview
 * @covers \WPBouncer\Admin\RuleLabels
 * @covers \WPBouncer\Admin\RuleCatalog
 * @covers \WPBouncer\Admin\RuleStatus
 * @covers \WPBouncer\Plugin::registered_rules
 */
final class RulesTabTest extends IntegrationTestCase {

	private const FORM = 'form.wpb-rules-form';

	/** @var AdminController */
	private $admin;

	public function set_up() {
		parent::set_up();
		$this->admin = new AdminController( $this->plugin );
		$this->fake_request();
		$GLOBALS['hook_suffix'] = 'toplevel_page_wp-bouncer';
		set_current_screen( 'toplevel_page_wp-bouncer' );
		// The uploads rule reads the .htaccess state and the last test result. Pin both to "healthy" so the
		// results do not depend on whether the machine running the tests can write to its uploads folder.
		update_option( UploadsGuard::STATE_OPTION, array( 'want' => 'x', 'ok' => true, 'broken' => false, 'time' => time() ) );
		delete_option( UploadsGuard::PROBE_OPTION );
	}

	public function tear_down() {
		unset( $GLOBALS['current_screen'], $GLOBALS['hook_suffix'] );
		parent::tear_down();
	}

	/* ---------------- helpers ---------------- */

	private function login( bool $network = false ): void {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		if ( $network && is_multisite() ) {
			grant_super_admin( $id );
		}
		wp_set_current_user( $id );
	}

	/**
	 * Render a tab.
	 *
	 * @param string               $tab Tab.
	 * @param array<string, mixed> $get Extra query arguments.
	 */
	private function render( string $tab = 'rules', array $get = array() ): string {
		$_GET = array_merge( array( 'tab' => $tab ), $get );
		ob_start();
		$this->admin->render();
		return (string) ob_get_clean();
	}

	private function notices(): string {
		ob_start();
		$this->admin->notices();
		return (string) ob_get_clean();
	}

	private function xpath( string $html ): \DOMXPath {
		$doc = new \DOMDocument();
		$was = libxml_use_internal_errors( true );
		$doc->loadHTML( '<?xml encoding="utf-8" ?>' . $html );
		libxml_clear_errors();
		libxml_use_internal_errors( $was );
		return new \DOMXPath( $doc );
	}

	/** @return array<string, mixed> */
	private function stored(): array {
		return (array) get_option( Settings::OPTION );
	}

	/**
	 * Submit a form the way a browser would and save it.
	 *
	 * @param string                                          $html   The page.
	 * @param (callable(array<string, mixed>): array<string, mixed>)|null $mutate Change the fields before posting.
	 * @return \WPBouncer\Tests\Integration\Redirected
	 */
	private function submit( string $html, ?callable $mutate = null ) {
		$post = FormFields::of( $html, self::FORM );
		if ( null !== $mutate ) {
			$post = $mutate( $post );
		}
		// WordPress adds slashes to $_POST before plugins see it; the handler removes them again.
		$_POST                     = wp_slash( $post );
		$_REQUEST                  = $_POST;
		$_SERVER['REQUEST_METHOD'] = 'POST';
		return $this->redirect_of( array( $this->admin, 'handle_save' ) );
	}

	/**
	 * A settings fixture that differs from the defaults in every rule and every field of every rule.
	 *
	 * @return array<string, mixed>
	 */
	private function non_default(): array {
		return require dirname( __DIR__, 2 ) . '/fixtures/rules-non-default.php';
	}

	/**
	 * Store settings: the defaults with whole rules replaced (a list in an override replaces the default list).
	 *
	 * @param array<string, mixed> $overrides Settings, with rules keyed by id.
	 */
	private function store( array $overrides ): void {
		$values = array_replace( Settings::defaults(), array_diff_key( $overrides, array( 'rules' => 1 ) ) );
		foreach ( (array) ( $overrides['rules'] ?? array() ) as $id => $rule ) {
			$values['rules'][ $id ] = array_merge( $values['rules'][ $id ], $rule );
		}
		update_option( Settings::OPTION, Settings::sanitize( $values ), true );
		$this->plugin->reload_settings();
	}

	/**
	 * Both kinds of administrator (the same on a single site).
	 *
	 * @return array<string, array{0: bool}>
	 */
	public static function admins(): array {
		return array(
			'site administrator'    => array( false ),
			'network administrator' => array( true ),
		);
	}

	/** Flatten nested settings into "a.b.c" => value for diffs. */
	private static function flatten( array $values, string $prefix = '' ): array {
		$out = array();
		foreach ( $values as $key => $value ) {
			$path = '' === $prefix ? (string) $key : $prefix . '.' . $key;
			if ( is_array( $value ) && array() !== $value && array_keys( $value ) !== range( 0, count( $value ) - 1 ) ) {
				$out += self::flatten( $value, $path );
			} else {
				$out[ $path ] = $value;
			}
		}
		return $out;
	}

	/* ---------------- round trip: saving the form unchanged changes nothing ---------------- */

	/**
	 * @dataProvider admins
	 */
	public function test_saving_the_rules_form_unchanged_changes_no_setting_with_defaults( bool $network ): void {
		$this->login( $network );
		$this->store( array() );
		$before = $this->stored();

		$r = $this->submit( $this->render() );

		$this->assertFalse( $r->is_error(), $r->message() );
		$this->assertSame( $before, $this->stored() );
	}

	/**
	 * @dataProvider admins
	 */
	public function test_saving_the_rules_form_unchanged_changes_no_setting_with_every_rule_non_default( bool $network ): void {
		$this->login( $network );
		$this->store( $this->non_default() );
		$before = $this->stored();
		$this->assertNotSame( Settings::defaults()['rules'], $before['rules'], 'the fixture is not the defaults' );

		$r = $this->submit( $this->render() );

		$this->assertFalse( $r->is_error(), $r->message() );
		$this->assertSame( $before, $this->stored() );
	}

	public function test_the_round_trip_catches_a_rule_missing_from_the_form(): void {
		// The guard works: dropping one rule's switch from the POST (what a partial that forgot an input would do) switches it off.
		$this->login( true );
		$this->store( array() );
		$before = $this->stored();

		$this->submit(
			$this->render(),
			static function ( array $post ): array {
				unset( $post['wp_bouncer']['rules']['waf'] );
				return $post;
			}
		);

		$this->assertTrue( $before['rules']['waf']['enabled'] );
		$this->assertFalse( $this->stored()['rules']['waf']['enabled'] );
	}

	/**
	 * @dataProvider admins
	 */
	public function test_changing_one_field_changes_only_that_field( bool $network ): void {
		$this->login( $network );
		$this->store( array() );
		$before = $this->stored();

		$this->submit(
			$this->render(),
			static function ( array $post ): array {
				unset( $post['wp_bouncer']['rules']['waf']['xss'] );
				return $post;
			}
		);

		$after = $this->stored();
		$this->assertNotSame( $before, $after );
		$a = self::flatten( $before );
		$b = self::flatten( $after );
		$changed = array_keys( array_filter( $b, static fn ( $v, $k ) => $a[ $k ] !== $v, ARRAY_FILTER_USE_BOTH ) );
		$this->assertSame( array( 'rules.waf.xss' ), $changed );
		$this->assertFalse( $after['rules']['waf']['xss'] );
	}

	public function test_the_country_rule_is_not_touched_by_saving_the_rules_tab(): void {
		$this->login( true );
		$this->store( $this->non_default() );
		$country = $this->stored()['rules']['country'];

		// Even a forged country field is ignored: the Rules tab does not own that rule.
		$this->submit(
			$this->render(),
			static function ( array $post ): array {
				$post['wp_bouncer']['rules']['country'] = array( 'enabled' => '', 'countries' => array( 'US' ) );
				return $post;
			}
		);

		$this->assertSame( $country, $this->stored()['rules']['country'] );
	}

	public function test_the_form_includes_third_party_rows_without_changing_the_round_trip(): void {
		$this->login( true );
		$this->add_third_party( 'login-accounts', 'My rule' );
		$this->store( $this->non_default() );
		$before = $this->stored();

		$r = $this->submit( $this->render() );

		$this->assertFalse( $r->is_error(), $r->message() );
		$this->assertSame( $before, $this->stored() );
	}

	/* ---------------- completeness ---------------- */

	/**
	 * @dataProvider admins
	 */
	public function test_every_rule_the_tab_owns_has_an_enabled_input_and_nothing_else_is_disabled( bool $network ): void {
		$this->login( $network );
		$html  = $this->render();
		$names = FormFields::names( $html, self::FORM );

		foreach ( Settings::TAB_FIELDS['rules'] as $field ) {
			$id = substr( $field, 6 );
			if ( is_multisite() && ! $network && 'uploads_php' === $id ) {
				continue; // Pinned for sub-site administrators: checked below.
			}
			$this->assertContains( "wp_bouncer[rules][$id][enabled]", $names, $id );
		}
		$this->assertSame( array(), preg_grep( '/\[rules\]\[country\]/', $names ), 'country settings belong to the Countries tab' );

		preg_match_all( '/<(?:input|textarea|select)\b[^>]*\sdisabled\b[^>]*>/', $html, $disabled );
		$pinned = array();
		foreach ( $disabled[0] as $tag ) {
			preg_match( '/name="([^"]+)"/', $tag, $m );
			$pinned[] = $m[1];
		}
		if ( is_multisite() && ! $network ) {
			// A sub-site administrator may not change these (the server pins them); everything else is live.
			sort( $pinned );
			$this->assertSame( array( 'wp_bouncer[rules][uploads_php][enabled]', 'wp_bouncer[rules][uploads_php][htaccess]' ), $pinned );
		} else {
			$this->assertSame( array(), $pinned );
		}
	}

	public function test_inputs_are_present_whether_or_not_a_panel_is_open(): void {
		$this->login( true );
		$closed = FormFields::names( $this->render(), self::FORM );
		$open   = FormFields::names( $this->render( 'rules', array( 'wpb_rule' => 'waf' ) ), self::FORM );

		$this->assertSame( $closed, $open );
		$this->assertContains( 'wp_bouncer[rules][waf][inspect_json]', $closed );
		$this->assertContains( 'wp_bouncer[rules][waf][excluded_params]', $closed );
	}

	/* ---------------- markup ---------------- */

	public function test_every_rule_and_category_has_an_anchor(): void {
		$this->login( true );
		$x = $this->xpath( $this->render() );

		foreach ( RuleCatalog::builtin_ids() as $id ) {
			$this->assertSame( 1, $x->query( "//*[@id='rule-$id']" )->length, $id );
		}
		foreach ( array_keys( RuleCatalog::CATEGORIES ) as $slug ) {
			$this->assertSame( 1, $x->query( "//section[@id='wpb-cat-$slug']" )->length, $slug );
			$this->assertSame( 1, $x->query( "//nav[contains(@class,'wpb-cat-nav')]//a[@href='#wpb-cat-$slug']" )->length, $slug );
		}
		$this->assertSame( 0, $x->query( "//*[@id='wpb-cat-other']" )->length, 'no Other category without third-party rules' );
	}

	public function test_rules_are_in_their_categories_in_the_owners_order(): void {
		$this->login( true );
		$x = $this->xpath( $this->render() );

		foreach ( RuleCatalog::CATEGORIES as $slug => $ids ) {
			$found = array();
			foreach ( $x->query( "//section[@id='wpb-cat-$slug']//div[@class='wpb-rule']" ) as $row ) {
				$found[] = substr( $row->getAttribute( 'id' ), 5 );
			}
			$this->assertSame( $ids, $found, $slug );
		}
	}

	public function test_each_switch_is_named_after_its_rule_and_is_a_switch(): void {
		$this->login( true );
		$x      = $this->xpath( $this->render() );
		$titles = RuleLabels::rules();

		foreach ( Settings::TAB_FIELDS['rules'] as $field ) {
			$id    = substr( $field, 6 );
			$input = $x->query( "//input[@name='wp_bouncer[rules][$id][enabled]']" )->item( 0 );
			$this->assertNotNull( $input, $id );
			$this->assertSame( 'switch', $input->getAttribute( 'role' ), $id );
			$name = $x->query( "../span[contains(@class,'screen-reader-text')]", $input )->item( 0 );
			$this->assertSame( $titles[ $id ][0], trim( $name->textContent ), $id );
		}
	}

	public function test_the_countries_and_traffic_switches_are_named_too(): void {
		$this->login( true );
		$countries = $this->xpath( $this->render( 'countries' ) );
		$traffic   = $this->xpath( $this->render( 'traffic' ) );

		$input = $countries->query( "//input[@name='wp_bouncer[rules][country][enabled]']" )->item( 0 );
		$this->assertSame( 'switch', $input->getAttribute( 'role' ) );
		$this->assertSame( 'Country blocking', trim( $countries->query( '../span[contains(@class,"screen-reader-text")]', $input )->item( 0 )->textContent ) );
		$input = $traffic->query( "//input[@name='wp_bouncer[traffic][enabled]']" )->item( 0 );
		$this->assertSame( 'switch', $input->getAttribute( 'role' ) );
		$this->assertSame( 'Record traffic', trim( $traffic->query( '../span[contains(@class,"screen-reader-text")]', $input )->item( 0 )->textContent ) );
	}

	public function test_headings_go_from_page_to_category_to_rule(): void {
		$this->login( true );
		$x = $this->xpath( $this->render() );

		$this->assertSame( 1, $x->query( '//h1' )->length );
		$this->assertSame( 4, $x->query( '//section[contains(@class,"wpb-category")]/h2' )->length );
		$this->assertSame( 11, $x->query( '//section[contains(@class,"wpb-category")]//div[contains(@class,"wpb-rule-text")]/h3' )->length );
		$this->assertSame( 0, $x->query( '//div[@class="wpb-rule"]//h2' )->length, 'no heading above h3 inside a rule' );
		$this->assertSame( 0, $x->query( '//summary//h1 | //summary//h2 | //summary//h3' )->length, 'no heading inside summary' );
	}

	public function test_a_rule_row_is_a_labelled_focus_target(): void {
		$this->login( true );
		$x   = $this->xpath( $this->render() );
		$row = $x->query( "//div[@id='rule-waf']" )->item( 0 );

		$this->assertSame( '-1', $row->getAttribute( 'tabindex' ) );
		$this->assertSame( 'group', $row->getAttribute( 'role' ) );
		$this->assertSame( 'rule-waf-title', $row->getAttribute( 'aria-labelledby' ) );
		$this->assertSame( 1, $x->query( "//h3[@id='rule-waf-title']" )->length );
		$this->assertSame( '-1', $x->query( "//section[@id='wpb-cat-block-lists']" )->item( 0 )->getAttribute( 'tabindex' ) );
		$summary = $x->query( "//div[@id='rule-waf']//details/summary" )->item( 0 );
		$this->assertSame( 'Settings: Web application firewall', preg_replace( '/\s+/', ' ', trim( $summary->textContent ) ) );
	}

	public function test_the_waf_card_keeps_the_json_inspection_checkbox(): void {
		$this->login( true );
		$x = $this->xpath( $this->render() );

		$this->assertSame( 1, $x->query( "//div[@id='rule-waf']//input[@name='wp_bouncer[rules][waf][inspect_json]']" )->length );
	}

	public function test_the_country_rule_is_a_status_card_with_a_link_and_no_inputs(): void {
		$this->login( true );
		$this->store( array( 'rules' => array( 'country' => array( 'enabled' => true, 'mode' => 'allow', 'countries' => array( 'DE', 'FR', 'NL' ), 'scope' => 'login' ) ) ) );
		$x = $this->xpath( $this->render() );

		$row = $x->query( "//div[@id='rule-country']" )->item( 0 );
		$this->assertSame( 0, $x->query( './/input | .//textarea | .//select | .//details', $row )->length );
		$this->assertStringContainsString( 'Admitting only 3 countries on login pages.', $row->textContent );
		$this->assertSame( 'On', trim( $x->query( ".//span[contains(@class,'wpb-state')]", $row )->item( 0 )->textContent ) );
		$link = $x->query( './/a[contains(@class,"button")]', $row )->item( 0 );
		$this->assertStringContainsString( 'tab=countries', $link->getAttribute( 'href' ) );
	}

	public function test_the_category_summary_counts_rules_that_are_on(): void {
		$this->login( true );
		$this->store( array( 'rules' => array( 'xmlrpc' => array( 'enabled' => false ), 'user_enumeration' => array( 'enabled' => false ) ) ) );
		$x = $this->xpath( $this->render() );

		$summary = $x->query( "//section[@id='wpb-cat-login-accounts']/p[contains(@class,'wpb-cat-summary')]" )->item( 0 );
		$this->assertSame( '1 of 3 rules on', trim( $summary->textContent ) );
		$this->assertStringContainsString( '2 of 3 rules on', $x->query( "//nav[contains(@class,'wpb-cat-nav')]" )->item( 0 )->textContent, 'block lists: ip blocklist and user agent' );
	}

	public function test_the_rate_limit_hint_is_neutral_and_not_counted_as_attention(): void {
		$this->login( true );
		$x = $this->xpath( $this->render() );

		$flag = $x->query( "//div[@id='rule-rate_limit']//p[contains(@class,'wpb-rule-flag')]" )->item( 0 );
		$this->assertNotNull( $flag );
		$this->assertStringContainsString( 'is-setup', $flag->getAttribute( 'class' ) );
		$this->assertStringContainsString( 'Before switching on:', $flag->textContent );
		$this->assertSame( 0, $x->query( "//*[contains(@class,'is-attention')]" )->length );
		$this->assertStringNotContainsString( 'needs attention', $x->query( "//section[@id='wpb-cat-scanners-floods']" )->item( 0 )->textContent );
	}

	public function test_the_uploads_probe_and_sync_forms_keep_their_nonce_next_to_the_action(): void {
		$this->login( true );
		$html = $this->render();

		// tests/e2e/run.sh finds the nonce with a regex that expects the action field to follow it.
		foreach ( array( 'wp_bouncer_uploads_probe', 'wp_bouncer_uploads_sync' ) as $action ) {
			$this->assertMatchesRegularExpression( '/name="_wpnonce" value="[a-z0-9]+"[^>]*>\s*<input type="hidden" name="_wp_http_referer"[^>]*>\s*<input type="hidden" name="action" value="' . $action . '"/', $html );
		}
		$this->assertSame( 1, preg_match_all( '/id="wpb-uploads-probe-form"/', $html ) );
		$this->assertSame( 'wpb-uploads-probe-form', $this->xpath( $html )->query( "//button[normalize-space()='Test now']" )->item( 0 )->getAttribute( 'form' ) );
	}

	/* ---------------- what opens ---------------- */

	/** @return string[] Ids of the rows whose settings are open. */
	private function open_rows( \DOMXPath $x ): array {
		$open = array();
		foreach ( $x->query( '//details[contains(@class,"wpb-rule-settings")]' ) as $details ) {
			if ( $details->hasAttribute( 'open' ) ) {
				$open[] = $details->parentNode->getAttribute( 'id' );
			}
		}
		return $open;
	}

	public function test_no_panel_is_open_by_default(): void {
		$this->login( true );

		$this->assertSame( array(), $this->open_rows( $this->xpath( $this->render() ) ) );
	}

	public function test_the_wpb_rule_argument_opens_that_panel_only(): void {
		$this->login( true );

		$this->assertSame( array( 'rule-waf' ), $this->open_rows( $this->xpath( $this->render( 'rules', array( 'wpb_rule' => 'waf' ) ) ) ) );
	}

	public function test_a_bad_wpb_rule_opens_nothing(): void {
		$this->login( true );
		foreach ( array( '../x', 'nope', 'country', '', 'WAF<script>', 'my_rule', 'waf<script>' ) as $value ) {
			$html = $this->render( 'rules', array( 'wpb_rule' => $value ) );
			$open = $this->open_rows( $this->xpath( $html ) );
			$this->assertSame( array(), $open, $value );
			$this->assertStringNotContainsString( '<script>', $html, $value );
		}
	}

	/* ---------------- status ---------------- */

	public function test_country_on_without_a_geo_database_is_flagged_with_a_link_to_tools(): void {
		$this->login( true );
		delete_option( Plugin::GEO_META_OPTION );
		$this->store( array( 'rules' => array( 'country' => array( 'enabled' => true, 'countries' => array( 'DE' ) ) ) ) );
		$x = $this->xpath( $this->render() );

		$flag = $x->query( "//div[@id='rule-country']//p[contains(@class,'wpb-rule-flag')]" )->item( 0 );
		$this->assertStringContainsString( 'is-attention', $flag->getAttribute( 'class' ) );
		$this->assertStringContainsString( 'Needs attention:', $flag->textContent );
		$this->assertStringContainsString( 'tab=tools', $x->query( './/a', $flag )->item( 0 )->getAttribute( 'href' ) );
		$this->assertSame( '3 of 3 rules on · 1 needs attention', preg_replace( '/\s+/', ' ', trim( $x->query( "//section[@id='wpb-cat-block-lists']/p[contains(@class,'wpb-cat-summary')]" )->item( 0 )->textContent ) ) );
	}

	public function test_country_on_with_no_countries_is_flagged_on_the_card_but_not_as_a_notice(): void {
		$this->login( true );
		update_option( Plugin::GEO_META_OPTION, array( 'rows' => 10 ) );
		$this->store( array( 'rules' => array( 'country' => array( 'enabled' => true, 'countries' => array() ) ) ) );

		$this->assertStringContainsString( 'blocks nobody', $this->render() );
		$this->assertStringNotContainsString( 'blocks nobody', $this->notices() );
	}

	public function test_a_broken_uploads_block_flags_the_card_opens_the_panel_and_links_from_the_notice(): void {
		$this->login( true );
		update_option( UploadsGuard::STATE_OPTION, array( 'want' => 'on:x', 'ok' => true, 'broken' => true, 'time' => time() ) );
		$x = $this->xpath( $this->render() );

		$flag = $x->query( "//div[@id='rule-uploads_php']//p[contains(@class,'wpb-rule-flag')]" )->item( 0 );
		$this->assertStringContainsString( 'Needs attention:', $flag->textContent );
		$this->assertStringNotContainsString( 'answered uploaded files (images too) with an error', $flag->textContent, 'the notice keeps that sentence; the card says it differently' );
		$this->assertContains( 'rule-uploads_php', $this->open_rows( $x ) );
		$this->assertSame( 'On', trim( $x->query( "//div[@id='rule-uploads_php']//span[contains(@class,'wpb-state')]" )->item( 0 )->textContent ) );

		$notice = $this->notices();
		$this->assertSame( 1, substr_count( $notice, 'answered uploaded files (images too) with an error' ) );
		$this->assertStringContainsString( 'wpb_rule=uploads_php', $notice );
		$this->assertStringContainsString( '#rule-uploads_php', $notice );
		$this->assertStringContainsString( 'Go to No PHP in uploads', $notice );
		$this->assertStringNotContainsString( 'See Rules', $notice );
	}

	public function test_an_unprotected_test_result_flags_the_card_but_is_not_a_notice(): void {
		$this->login( true );
		update_option( UploadsGuard::STATE_OPTION, array( 'want' => 'x', 'ok' => true, 'broken' => false, 'time' => time() ) ); // Written fine: only the test result is wrong.
		update_option( UploadsGuard::PROBE_OPTION, array( 'result' => 'unprotected', 'detail' => 'HTTP 200', 'time' => time() ) );
		$html = $this->render();
		$x    = $this->xpath( $html );

		$this->assertStringContainsString( 'scripts can still run from the uploads folder', $x->query( "//div[@id='rule-uploads_php']//p[contains(@class,'wpb-rule-flag')]" )->item( 0 )->textContent );
		$this->assertStringNotContainsString( 'scripts can still run', $this->notices() );
		// The probe result line is printed once, in the uploads panel (tests/e2e/run.sh counts it).
		$this->assertSame( 1, substr_count( $html, 'Not protected: the server ran a test script' ) );
	}

	public function test_a_paused_country_rule_is_a_status_reason_and_the_notice_links_to_the_proxy_setting(): void {
		$this->login( true );
		$this->store(
			array(
				'geo_source' => 'header',
				'geo_header' => 'CF-IPCountry',
				'rules'      => array( 'country' => array( 'enabled' => true, 'countries' => array( 'DE' ) ) ),
			)
		);
		delete_option( Plugin::GEO_META_OPTION );
		$this->assertTrue( $this->plugin->country_paused() );

		$notice = $this->notices();
		$this->assertStringContainsString( 'Country blocking is paused', $notice );
		$this->assertStringContainsString( 'notice-warning', $notice );
		$this->assertStringContainsString( '#wpb-proxies', $notice );
		$this->assertStringNotContainsString( 'no geo database is loaded', $notice );
		$this->assertStringContainsString( 'no trusted proxy is listed', $this->render() );
	}

	public function test_the_existing_geo_database_notice_is_unchanged(): void {
		$this->login( true );
		delete_option( Plugin::GEO_META_OPTION );
		$this->store( array( 'rules' => array( 'country' => array( 'enabled' => true, 'countries' => array( 'DE' ) ) ) ) );

		$notice = $this->notices();
		$this->assertStringContainsString( 'no geo database is loaded', $notice );
		$this->assertStringContainsString( 'notice-error', $notice );
		$this->assertStringContainsString( 'tab=tools', $notice );
	}

	/* ---------------- redirects ---------------- */

	public function test_the_uploads_actions_return_to_the_uploads_row_with_its_panel_open(): void {
		$this->login( true );
		$_POST                     = array( '_wpnonce' => wp_create_nonce( 'wp_bouncer_uploads_sync' ) );
		$_REQUEST                  = $_POST;
		$_SERVER['REQUEST_METHOD'] = 'POST';

		$r = $this->redirect_of( array( $this->admin, 'handle_uploads_sync' ) );

		$this->assertStringContainsString( 'tab=rules', $r->location );
		$this->assertStringContainsString( 'wpb_rule=uploads_php', $r->location );
		$this->assertStringEndsWith( '#rule-uploads_php', $r->location );
	}

	public function test_rule_url_points_at_the_rules_panel_or_the_countries_tab(): void {
		$this->assertStringContainsString( 'wpb_rule=waf', AdminController::rule_url( 'waf' ) );
		$this->assertStringEndsWith( '#rule-waf', AdminController::rule_url( 'waf' ) );
		$this->assertStringContainsString( 'tab=countries', AdminController::rule_url( 'country' ) );
		$this->assertStringNotContainsString( 'wpb_rule', AdminController::rule_url( 'my_rule' ) );
	}

	/* ---------------- third-party rules ---------------- */

	/**
	 * Add a rule to the chain and describe it.
	 *
	 * @param string $category Category slug to declare ('' for no declaration).
	 * @param string $title    Title to declare.
	 * @param string $id       Rule id.
	 */
	private function add_third_party( string $category, string $title, string $id = 'my_rule' ): void {
		add_filter(
			'wp_bouncer_rules',
			static function ( $rules ) use ( $id ) {
				$rules[] = new class( $id ) extends AbstractRule {
					/** @var string */
					private $rule_id;

					public function __construct( string $id ) {
						parent::__construct( array( 'enabled' => true ) );
						$this->rule_id = $id;
					}

					public function id(): string {
						return $this->rule_id;
					}

					public function inspect( \WPBouncer\Firewall\Request $request ): ?\WPBouncer\Firewall\Verdict {
						return null;
					}
				};
				return $rules;
			}
		);
		if ( '' !== $category ) {
			add_filter(
				'wp_bouncer_rule_info',
				static function ( $info ) use ( $id, $category, $title ) {
					$info[ $id ] = array( 'category' => $category, 'title' => $title );
					return $info;
				}
			);
		}
		$this->plugin->reload_settings();
	}

	public function test_a_described_third_party_rule_appears_in_its_category_with_an_escaped_title_and_no_switch(): void {
		$this->login( true );
		$this->add_third_party( 'login-accounts', '<b>X</b><script>alert(1)</script>' );
		$html = $this->render();
		$x    = $this->xpath( $html );

		$row = $x->query( "//section[@id='wpb-cat-login-accounts']//div[@id='rule-x-my_rule']" )->item( 0 );
		$this->assertNotNull( $row );
		$this->assertSame( 'Xalert(1)', trim( $x->query( './/h3', $row )->item( 0 )->textContent ) );
		$this->assertStringNotContainsString( '<b>X</b>', $html );
		$this->assertStringNotContainsString( '<script>alert(1)', $html );
		$this->assertSame( 0, $x->query( './/input | .//details', $row )->length );
		$this->assertSame( 'my_rule', trim( $x->query( './/code', $row )->item( 0 )->textContent ) );
		$this->assertSame( 'On', trim( $x->query( ".//span[contains(@class,'wpb-state')]", $row )->item( 0 )->textContent ) );
		$this->assertStringContainsString( 'Managed by the plugin that added it.', $row->textContent );
		$this->assertStringContainsString( '4 of 4 rules on', $x->query( "//section[@id='wpb-cat-login-accounts']/p[contains(@class,'wpb-cat-summary')]" )->item( 0 )->textContent );
		$this->assertStringNotContainsString( 'my_rule', implode( ' ', FormFields::names( $html, self::FORM ) ) );
	}

	public function test_an_undescribed_third_party_rule_appears_under_other_with_its_id(): void {
		$this->login( true );
		$this->add_third_party( '', '' );
		$x = $this->xpath( $this->render() );

		$row = $x->query( "//section[@id='wpb-cat-other']//div[@id='rule-x-my_rule']" )->item( 0 );
		$this->assertNotNull( $row );
		$this->assertSame( 'my_rule', trim( $x->query( './/h3', $row )->item( 0 )->textContent ) );
		$this->assertSame( 'wpb-cat-other', $x->query( '//section[contains(@class,"wpb-category")]' )->item( 4 )->getAttribute( 'id' ), 'Other comes last' );
	}

	public function test_third_party_ids_are_escaped_and_never_reach_an_include_path(): void {
		$this->login( true );
		$evil = '../../wp-config"><img src=x onerror=alert(1)>';
		$this->add_third_party( '', '', $evil );
		$html = $this->render();

		$this->assertStringNotContainsString( '<img src=x', $html );
		$this->assertStringContainsString( esc_html( $evil ), $html );
		$x = $this->xpath( $html );
		$this->assertSame( 1, $x->query( '//section[@id="wpb-cat-other"]//div[@class="wpb-rule"]' )->length );
	}

	public function test_a_third_party_rule_that_throws_does_not_break_the_page(): void {
		$this->login( true );
		add_filter(
			'wp_bouncer_rules',
			static function ( $rules ) {
				$rules[] = new class() implements RuleInterface {
					public function id(): string {
						return 'boom';
					}

					public function is_enabled(): bool {
						throw new \RuntimeException( 'broken add-on' );
					}

					public function inspect( \WPBouncer\Firewall\Request $request ): ?\WPBouncer\Firewall\Verdict {
						return null;
					}
				};
				$rules[] = new class() implements RuleInterface {
					public function id(): string {
						throw new \RuntimeException( 'worse' );
					}

					public function is_enabled(): bool {
						return true;
					}

					public function inspect( \WPBouncer\Firewall\Request $request ): ?\WPBouncer\Firewall\Verdict {
						return null;
					}
				};
				return $rules;
			}
		);
		$this->plugin->reload_settings();
		$x = $this->xpath( $this->render() );

		$this->assertSame( 'Unknown', trim( $x->query( "//div[@id='rule-x-boom']//span[contains(@class,'wpb-state')]" )->item( 0 )->textContent ) );
		$this->assertSame( 2, $x->query( '//section[@id="wpb-cat-other"]//div[@class="wpb-rule"]' )->length );
		$this->assertSame( 1, $x->query( "//div[@id='rule-waf']" )->length, 'the rest of the page rendered' );
	}

	public function test_third_party_anchors_have_their_own_prefix_and_cannot_hit_built_in_ids(): void {
		$this->login( true );
		$this->add_third_party( '', '', 'waf-title' );
		$x = $this->xpath( $this->render() );

		$this->assertSame( 1, $x->query( "//*[@id='rule-waf-title']" )->length, 'the built-in title id is untouched' );
		$this->assertSame( 'Web', substr( trim( $x->query( "//h3[@id='rule-waf-title']" )->item( 0 )->textContent ), 0, 3 ) );
		$this->assertSame( 1, $x->query( "//div[@id='rule-x-waf-title']" )->length );
	}

	public function test_a_real_rule_called_unknown_1_is_not_taken_for_a_failed_one(): void {
		$this->login( true );
		$this->add_third_party( '', '', 'unknown-1' );
		add_filter(
			'wp_bouncer_rules',
			static function ( $rules ) {
				$rules[] = new class() implements RuleInterface {
					public function id(): string {
						throw new \RuntimeException( 'no id' );
					}

					public function is_enabled(): bool {
						return true;
					}

					public function inspect( \WPBouncer\Firewall\Request $request ): ?\WPBouncer\Firewall\Verdict {
						return null;
					}
				};
				return $rules;
			}
		);
		$this->plugin->reload_settings();
		$x = $this->xpath( $this->render() );

		$this->assertSame( 2, $x->query( '//section[@id="wpb-cat-other"]//div[@class="wpb-rule"]' )->length );
		$this->assertSame( 'unknown-1', trim( $x->query( "//div[@id='rule-x-unknown-1']//h3" )->item( 0 )->textContent ) );
		$this->assertStringContainsString( 'Unknown rule', $x->query( '//section[@id="wpb-cat-other"]' )->item( 0 )->textContent );
	}

	public function test_a_built_in_rule_taken_out_of_the_chain_is_shown_as_removed_and_its_switch_still_saves(): void {
		$this->login( true );
		$this->store( array() );
		add_filter(
			'wp_bouncer_rules',
			static function ( $rules ) {
				return array_values( array_filter( $rules, static fn ( $rule ) => 'xmlrpc' !== $rule->id() ) );
			}
		);
		$this->plugin->reload_settings();
		$before = $this->stored();
		$html   = $this->render();
		$x      = $this->xpath( $html );

		$state = $x->query( "//div[@id='rule-xmlrpc']//span[contains(@class,'wpb-state')]" )->item( 0 );
		$this->assertSame( 'Removed by a plugin', trim( $state->textContent ) );
		$this->assertFalse( $state->hasAttribute( 'data-saved' ) );
		$this->assertStringContainsString( '2 of 3 rules on', $x->query( "//section[@id='wpb-cat-login-accounts']/p[contains(@class,'wpb-cat-summary')]" )->item( 0 )->textContent );

		$this->submit( $html );
		$this->assertSame( $before, $this->stored(), 'the stored switch is not lost' );
		$this->assertSame( 'On', trim( $x->query( "//div[@id='rule-waf']//span[contains(@class,'wpb-state')]" )->item( 0 )->textContent ) );
	}

	public function test_the_script_gets_every_string_it_uses(): void {
		$this->login( true );
		$js = (string) file_get_contents( dirname( __DIR__, 3 ) . '/wp-bouncer/assets/admin.js' );
		preg_match_all( '/\bi18n\.(\w+)/', $js, $m );
		$this->assertNotEmpty( $m[1] );

		wp_scripts()->registered = array();
		$this->admin->enqueue_assets( 'toplevel_page_wp-bouncer' );
		$data = (string) wp_scripts()->get_data( 'wp-bouncer-admin', 'data' );
		preg_match( '/var wpBouncer = (\{.*\});/s', $data, $json );
		$localized = json_decode( $json[1], true );

		foreach ( array_unique( $m[1] ) as $key ) {
			$this->assertArrayHasKey( $key, $localized['i18n'], "admin.js uses i18n.$key" );
			$this->assertNotSame( '', $localized['i18n'][ $key ], $key );
		}
	}

	public function test_third_party_info_for_built_in_rules_or_rules_not_in_the_chain_is_ignored(): void {
		$this->login( true );
		add_filter(
			'wp_bouncer_rule_info',
			static function ( $info ) {
				$info['waf']   = array( 'category' => 'other', 'title' => 'Relabelled' );
				$info['ghost'] = array( 'category' => 'other', 'title' => 'Ghost' );
				return $info;
			}
		);
		$html = $this->render();

		$this->assertStringNotContainsString( 'Relabelled', $html );
		$this->assertStringNotContainsString( 'Ghost', $html );
	}

	public function test_the_rule_chain_is_built_once_per_request_when_the_firewall_ran(): void {
		$this->login( true );
		$calls = 0;
		add_filter(
			'wp_bouncer_rules',
			static function ( $rules ) use ( &$calls ) {
				++$calls;
				return $rules;
			}
		);
		$this->plugin->reload_settings();

		$this->plugin->run_firewall();
		$this->render();
		$this->render( 'dashboard' );

		$this->assertSame( 1, $calls );
	}

	public function test_saving_settings_rebuilds_the_chain_with_the_new_settings(): void {
		$this->login( true );
		$this->store( array( 'rules' => array( 'xmlrpc' => array( 'enabled' => true ) ) ) );
		$this->plugin->registered_rules();
		$this->store( array( 'rules' => array( 'xmlrpc' => array( 'enabled' => false ) ) ) );

		$enabled = array();
		foreach ( $this->plugin->registered_rules() as $rule ) {
			$enabled[ $rule->id() ] = $rule->is_enabled();
		}
		$this->assertFalse( $enabled['xmlrpc'] );
	}

	/* ---------------- Dashboard ---------------- */

	public function test_the_dashboard_has_no_rules_list_or_switches(): void {
		$this->login( true );
		$this->add_third_party( 'scanners-floods', 'Bots' );
		$x = $this->xpath( $this->render( 'dashboard' ) );

		$this->assertSame( 0, $x->query( '//section[contains(@class,"wpb-overview")]' )->length );
		$this->assertSame( 0, $x->query( '//form[.//input[@name="action" and @value="wp_bouncer_toggle_rule"]]' )->length );
		$this->assertSame( 0, $x->query( '//input[@name="rule"]' )->length );
	}

	public function test_dashboard_top_countries_mark_blocked_countries(): void {
		global $wpdb;
		$this->login( true );
		$this->store( array( 'rules' => array( 'country' => array( 'enabled' => true, 'mode' => 'block', 'countries' => array( 'RU' ) ) ) ) );
		foreach ( array( 'RU', 'US' ) as $code ) {
			$wpdb->insert(
				$wpdb->prefix . 'bouncer_log',
				array(
					'ip'         => '203.0.113.5',
					'rule'       => 'waf',
					'action'     => 'blocked',
					'country'    => $code,
					'created_at' => gmdate( 'Y-m-d H:i:s', time() - 60 ),
				)
			);
		}
		$x    = $this->xpath( $this->render( 'dashboard' ) );
		$rows = $x->query( '//section[h2[contains(.,"Top countries")]]//tr' );
		$this->assertSame( 2, $rows->length );
		$badges = $x->query( '//section[h2[contains(.,"Top countries")]]//span[contains(@class,"wpb-country-blocked")]' );
		$this->assertSame( 1, $badges->length, 'only the blocked country has a badge' );
		$this->assertSame( 'Blocked', trim( $badges->item( 0 )->textContent ) );
		$this->assertStringContainsString( \WPBouncer\Geo\Countries::name( 'RU' ), $badges->item( 0 )->parentNode->textContent );
	}

	public function test_the_toggle_handler_flips_one_rule_and_keeps_the_others(): void {
		$this->login( true );
		$this->store( array() );
		$before = $this->stored();
		$_POST                     = array( '_wpnonce' => wp_create_nonce( 'wp_bouncer_toggle_rule' ), 'rule' => 'xmlrpc' );
		$_REQUEST                  = $_POST;
		$_SERVER['REQUEST_METHOD'] = 'POST';

		$this->redirect_of( array( $this->admin, 'handle_toggle_rule' ) );

		$after = $this->stored();
		$this->assertTrue( $before['rules']['xmlrpc']['enabled'] );
		$this->assertFalse( $after['rules']['xmlrpc']['enabled'] );
		$before['rules']['xmlrpc']['enabled'] = false;
		$this->assertSame( $before, $after );
	}

	public function test_the_widget_counts_rules_the_way_the_overview_does(): void {
		$this->login( true );
		$this->store( $this->non_default() );
		$expected = count( array_filter( $this->stored()['rules'], static fn ( $rule ) => ! empty( $rule['enabled'] ) ) );

		ob_start();
		( new \WPBouncer\Admin\DashboardWidget( $this->plugin ) )->render();
		$out = (string) ob_get_clean();

		$this->assertStringContainsString( "($expected of 11 rules on)", $out );
	}
}
