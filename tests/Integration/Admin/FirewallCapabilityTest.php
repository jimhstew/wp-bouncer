<?php
/**
 * The wpb_manage_firewall capability: single site vs multisite.
 *
 * The same tests run in both modes (WP_MULTISITE=1 switches the library):
 * on a single site the administrator holds the capability, on multisite only a
 * super admin does. There are no REST routes in the plugin; its AJAX action
 * (geo step) is covered in AdminControllerTest.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Integration\Admin;

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\FirewallCapability;
use WPBouncer\Settings;
use WPBouncer\Tests\Integration\IntegrationTestCase;

/**
 * @covers \WPBouncer\Admin\FirewallCapability
 * @covers \WPBouncer\Admin\AdminController
 * @covers \WPBouncer\Settings
 */
final class FirewallCapabilityTest extends IntegrationTestCase {

	/** @var AdminController */
	private $admin;

	public function set_up() {
		parent::set_up();
		$this->admin = new AdminController( $this->plugin );
		$this->fake_request();
	}

	private function site_admin(): int {
		$id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $id );
		return $id;
	}

	private function network_admin(): int {
		$id = $this->site_admin();
		if ( is_multisite() ) {
			grant_super_admin( $id );
			wp_set_current_user( $id );
		}
		return $id;
	}

	/**
	 * @param array<string, mixed> $post Fields.
	 */
	private function post( string $action, array $post = array() ): void {
		$post['_wpnonce']          = wp_create_nonce( $action );
		$_POST                     = $post;
		$_REQUEST                  = $post;
		$_SERVER['REQUEST_METHOD'] = 'POST';
	}

	/** @return array<string, mixed> */
	private function stored(): array {
		return (array) get_option( Settings::OPTION );
	}

	public function test_the_meta_capability_maps_by_site_type(): void {
		$this->assertSame( array( is_multisite() ? 'manage_network_options' : 'manage_options' ), FirewallCapability::map( array( 'x' ), 'wpb_manage_firewall' ) );
		$this->assertSame( array( 'x' ), FirewallCapability::map( array( 'x' ), 'edit_posts' ), 'other capabilities are untouched' );

		$this->site_admin();
		$this->assertSame( ! is_multisite(), current_user_can( 'wpb_manage_firewall' ) );
		$this->network_admin();
		$this->assertTrue( current_user_can( 'wpb_manage_firewall' ) );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'editor' ) ) );
		$this->assertFalse( current_user_can( 'wpb_manage_firewall' ) );
		wp_set_current_user( 0 );
		$this->assertFalse( current_user_can( 'wpb_manage_firewall' ) );
	}

	/** @return array<string, array{string, string, array<string, string>}> */
	public static function server_wide_handlers(): array {
		return array(
			'uploads probe' => array( 'handle_uploads_probe', 'wp_bouncer_uploads_probe', array() ),
			'uploads sync'  => array( 'handle_uploads_sync', 'wp_bouncer_uploads_sync', array() ),
			'geo url'       => array( 'handle_geo_import', 'wp_bouncer_geo_import', array( 'geo_url' => 'https://download.db-ip.com/free/x.csv.gz' ) ),
		);
	}

	/**
	 * @dataProvider server_wide_handlers
	 * @param array<string, string> $post Fields.
	 */
	public function test_a_multisite_site_admin_gets_403_for_server_wide_actions( string $method, string $action, array $post ): void {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite only.' );
		}
		$this->site_admin();
		$this->post( $action, $post );
		$before = $this->stored();
		add_filter(
			'pre_http_request',
			function () {
				$this->fail( 'no request may be made' );
			}
		);

		$e = $this->die_of( array( $this->admin, $method ) );

		$this->assertStringContainsString( 'permission', $e->getMessage() );
		$this->assertSame( 403, $e->getCode() );
		$this->assertSame( $before, $this->stored() );
	}

	public function test_a_network_admin_passes_the_server_wide_checks(): void {
		$this->network_admin();
		$this->post( 'wp_bouncer_uploads_sync' );
		$r = $this->redirect_of( array( $this->admin, 'handle_uploads_sync' ) );
		$this->assertStringContainsString( 'tab=rules', $r->location );

		// A URL import by a permitted user gets as far as the host check (nothing is fetched).
		add_filter(
			'pre_http_request',
			function () {
				$this->fail( 'a host off the list must be refused before any request' );
			}
		);
		$this->post( 'wp_bouncer_geo_import', array( 'geo_url' => 'https://93.184.216.34/geo.csv' ) );
		$r = $this->redirect_of( array( $this->admin, 'handle_geo_import' ) );
		$this->assertTrue( $r->is_error() );
		$this->assertSame( 'Download failed: That host is not on the list of allowed download hosts.', $r->message() );
	}

	public function test_http_urls_are_refused_even_for_a_listed_host(): void {
		$this->network_admin();
		add_filter(
			'pre_http_request',
			function () {
				$this->fail( 'no request may be made' );
			}
		);
		$this->post( 'wp_bouncer_geo_import', array( 'geo_url' => 'http://download.db-ip.com/free/x.csv.gz' ) );
		$r = $this->redirect_of( array( $this->admin, 'handle_geo_import' ) );
		$this->assertTrue( $r->is_error() );
	}

	public function test_a_site_admin_may_still_upload_a_geo_file(): void {
		$this->site_admin();
		$this->post( 'wp_bouncer_geo_import' );
		$_FILES = array(
			'geo_file' => array(
				'name'     => 'geo.csv',
				'tmp_name' => $this->uploads_dir . '/not-really-uploaded.csv',
				'error'    => UPLOAD_ERR_OK,
				'size'     => 1,
			),
		);

		$r = $this->redirect_of( array( $this->admin, 'handle_geo_import' ) );

		// Past the permission check: only the "really uploaded" test stops it.
		$this->assertSame( 'geo_no_arrive', $r->code() );
		$_FILES = array();
	}

	/**
	 * @param string[] $patterns Patterns in the form.
	 * @return string[] Stored patterns.
	 */
	private function save_patterns( array $patterns ): array {
		$this->post(
			'wp_bouncer_save',
			array(
				'tab'        => 'rules',
				'wp_bouncer' => array( 'rules' => array( 'user_agent' => array( 'patterns' => wp_slash( implode( "\n", $patterns ) ) ) ) ),
			)
		);
		$this->redirect_of( array( $this->admin, 'handle_save' ) );
		return $this->stored()['rules']['user_agent']['patterns'];
	}

	public function test_regex_patterns_need_the_capability_but_plain_ones_and_existing_regexes_do_not(): void {
		$this->set_settings( array( 'rules' => array( 'user_agent' => array( 'patterns' => array( '/^old\//i', 'oldplain' ) ) ) ) );
		$this->site_admin();

		$saved = $this->save_patterns( array( '/^old\//i', 'oldplain', 'newplain', '/^new\//i' ) );

		if ( is_multisite() ) {
			$this->assertSame( array( '/^old\//i', 'oldplain', 'newplain' ), $saved, 'the new regex is dropped, the existing one kept' );
		} else {
			$this->assertSame( array( '/^old\//i', 'oldplain', 'newplain', '/^new\//i' ), $saved );
		}

		$this->network_admin();
		$this->assertContains( '/^new\//i', $this->save_patterns( array( '/^old\//i', '/^new\//i' ) ), 'a network admin can add regexes' );
	}

	public function test_the_htaccess_switch_cannot_be_changed_by_a_multisite_site_admin(): void {
		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'htaccess' => true ) ) ) );
		$this->site_admin();
		$this->post(
			'wp_bouncer_save',
			array(
				'tab'        => 'rules',
				'wp_bouncer' => array( 'rules' => array( 'uploads_php' => array( 'check_uploads' => '1' ) ) ), // The disabled checkbox is not submitted.
			)
		);
		$this->redirect_of( array( $this->admin, 'handle_save' ) );

		$this->assertSame( is_multisite(), $this->stored()['rules']['uploads_php']['htaccess'], 'kept on multisite, switched off on a single site' );
	}

	public function test_toggling_a_rule_is_not_blocked_and_keeps_the_privileged_values(): void {
		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'htaccess' => true ), 'user_agent' => array( 'patterns' => array( '/^old\//i' ) ) ) ) );
		$this->site_admin();
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'waf' ) );
		$this->redirect_of( array( $this->admin, 'handle_toggle_rule' ) );

		$this->assertTrue( $this->stored()['rules']['uploads_php']['htaccess'] );
		$this->assertContains( '/^old\//i', $this->stored()['rules']['user_agent']['patterns'] );
	}

	public function test_the_uploads_rule_toggle_is_network_admin_only_on_multisite(): void {
		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'enabled' => true ) ) ) );
		$this->site_admin();
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'uploads_php' ) );

		$r = $this->redirect_of( array( $this->admin, 'handle_toggle_rule' ) );

		if ( is_multisite() ) {
			$this->assertTrue( $r->is_error() );
			$this->assertSame( 'That setting is managed by your network administrator.', $r->message() );
			$this->assertTrue( $this->stored()['rules']['uploads_php']['enabled'] );
		} else {
			$this->assertFalse( $this->stored()['rules']['uploads_php']['enabled'] );
		}
	}

	public function test_a_network_admin_can_toggle_the_uploads_rule(): void {
		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'enabled' => true ) ) ) );
		$this->network_admin();
		$this->post( 'wp_bouncer_toggle_rule', array( 'rule' => 'uploads_php' ) );
		$this->redirect_of( array( $this->admin, 'handle_toggle_rule' ) );
		$this->assertFalse( $this->stored()['rules']['uploads_php']['enabled'] );
	}

	public function test_a_rules_tab_save_cannot_turn_the_uploads_rule_off_on_multisite(): void {
		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'enabled' => true, 'htaccess' => true ) ) ) );
		$this->site_admin();
		// A disabled checkbox is not submitted; neither would a forged form omit nothing else.
		$this->post( 'wp_bouncer_save', array( 'tab' => 'rules', 'wp_bouncer' => array( 'rules' => array( 'uploads_php' => array( 'check_uploads' => '1' ) ) ) ) );
		$this->redirect_of( array( $this->admin, 'handle_save' ) );

		$this->assertSame( is_multisite(), $this->stored()['rules']['uploads_php']['enabled'] );
		$this->assertSame( is_multisite(), $this->stored()['rules']['uploads_php']['htaccess'] );
	}

	public function test_other_save_paths_keep_the_privileged_values_too(): void {
		$this->set_settings( array( 'rules' => array( 'uploads_php' => array( 'enabled' => true, 'htaccess' => true ), 'user_agent' => array( 'patterns' => array( '/^old\//i' ) ) ) ) );
		$this->site_admin();
		$this->post( 'wp_bouncer_ip_setup', array( 'fix' => 'use_remote_addr' ) );
		$this->redirect_of( array( $this->admin, 'handle_ip_setup' ) );

		$rules = $this->stored()['rules'];
		$this->assertTrue( $rules['uploads_php']['enabled'] );
		$this->assertTrue( $rules['uploads_php']['htaccess'] );
		$this->assertContains( '/^old\//i', $rules['user_agent']['patterns'] );
		$this->assertSame( 'remote_addr', $this->stored()['ip_source'] );
	}

	public function test_a_site_admin_posting_a_url_together_with_a_file_takes_the_file_path(): void {
		$this->site_admin();
		$this->post( 'wp_bouncer_geo_import', array( 'geo_url' => 'https://download.db-ip.com/free/x.csv.gz' ) );
		$_FILES = array(
			'geo_file' => array(
				'name'     => 'geo.csv',
				'tmp_name' => $this->uploads_dir . '/not-really-uploaded.csv',
				'error'    => UPLOAD_ERR_OK,
				'size'     => 1,
			),
		);
		add_filter(
			'pre_http_request',
			function () {
				$this->fail( 'the URL must be ignored when a file is sent' );
			}
		);

		$r = $this->redirect_of( array( $this->admin, 'handle_geo_import' ) );

		$this->assertSame( 'geo_no_arrive', $r->code(), 'no 403: the file path ran' );
		$_FILES = array();
	}

	/* ---------------- redirects ---------------- */

	/**
	 * Answer the importer's requests from a script; returns a counter of requests made.
	 *
	 * @param array<int, array{0: int, 1: string, 2?: string}> $script Status, Location (or ''), body per request.
	 * @return \ArrayObject<string, mixed> Holds 'urls'.
	 */
	private function script_http( array $script ): \ArrayObject {
		$log = new \ArrayObject( array( 'urls' => array() ) );
		add_filter( 'wp_bouncer_geo_import_hosts', static fn( $h ) => array_merge( $h, array( '93.184.216.34' ) ) );
		add_filter(
			'pre_http_request',
			function ( $pre, $args, $url ) use ( $script, $log ) {
				$this->assertSame( 0, $args['redirection'], 'the HTTP API must not follow redirects itself' );
				$i                = count( $log['urls'] );
				$log['urls']      = array_merge( $log['urls'], array( $url ) );
				$step             = $script[ min( $i, count( $script ) - 1 ) ];
				$headers          = '' !== $step[1] ? array( 'location' => $step[1] ) : array();
				file_put_contents( $args['filename'], $step[2] ?? '' );
				return array( 'headers' => $headers, 'body' => '', 'response' => array( 'code' => $step[0], 'message' => '' ), 'cookies' => array(), 'filename' => $args['filename'] );
			},
			10,
			3
		);
		return $log;
	}

	private function import_url( string $url ): \WPBouncer\Tests\Integration\Redirected {
		$this->network_admin();
		$this->post( 'wp_bouncer_geo_import', array( 'geo_url' => $url ) );
		return $this->redirect_of( array( $this->admin, 'handle_geo_import' ) );
	}

	public function test_a_redirect_to_an_unlisted_host_is_refused_without_a_second_request(): void {
		$log = $this->script_http( array( array( 302, 'https://198.51.100.7/geo.csv' ) ) );
		$r   = $this->import_url( 'https://93.184.216.34/geo.csv' );

		$this->assertTrue( $r->is_error() );
		$this->assertCount( 1, $log['urls'] );
		$this->assertNull( $this->plugin->geo_import()->status() );
	}

	public function test_a_redirect_downgrading_to_http_is_refused(): void {
		$log = $this->script_http( array( array( 301, 'http://93.184.216.34/geo.csv' ) ) );
		$r   = $this->import_url( 'https://93.184.216.34/geo.csv' );

		$this->assertTrue( $r->is_error() );
		$this->assertCount( 1, $log['urls'] );
	}

	public function test_more_than_three_redirects_are_refused(): void {
		$log = $this->script_http( array( array( 302, '/a' ), array( 302, '/b' ), array( 302, '/c' ), array( 302, '/d' ) ) );
		$r   = $this->import_url( 'https://93.184.216.34/geo.csv' );

		$this->assertTrue( $r->is_error() );
		$this->assertCount( 4, $log['urls'], 'the original request plus three hops' );
	}

	public function test_a_relative_redirect_to_the_same_host_is_followed(): void {
		$csv = (string) file_get_contents( dirname( __DIR__, 2 ) . '/fixtures/geo-sample.csv' );
		$log = $this->script_http( array( array( 302, '/files/real.csv' ), array( 200, '', $csv ) ) );
		$r   = $this->import_url( 'https://93.184.216.34/geo.csv' );

		$this->assertFalse( $r->is_error() );
		$this->assertSame( array( 'https://93.184.216.34/geo.csv', 'https://93.184.216.34/files/real.csv' ), $log['urls'] );
		$this->assertNotNull( $this->plugin->geo_import()->status() );
	}
}
