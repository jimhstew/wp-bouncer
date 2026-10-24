<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use WPBouncer\Rules\UserEnumerationRule;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Rules\UserEnumerationRule
 */
final class UserEnumerationRuleTest extends TestCase {

	private function rule( array $overrides = array() ): UserEnumerationRule {
		return new UserEnumerationRule(
			array_merge(
				array(
					'enabled'           => true,
					'block_author_scan' => true,
					'block_rest_users'  => true,
				),
				$overrides
			)
		);
	}

	public function test_blocks_author_id_scans(): void {
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'query' => array( 'author' => '1' ) ) ) ) );
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'query' => array( 'author' => '2abc' ) ) ) ) );
	}

	public function test_author_slug_queries_are_fine(): void {
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'query' => array( 'author' => 'jane' ) ) ) ) );
	}

	public function test_admin_author_filter_is_allowed(): void {
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/wp-admin/edit.php?author=1', 'query' => array( 'author' => '1' ) ) ) ) );
	}

	public function test_blocks_rest_user_listing(): void {
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/wp-json/wp/v2/users' ) ) ) );
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/wp-json/wp/v2/users/1' ) ) ) );
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'query' => array( 'rest_route' => '/wp/v2/users' ) ) ) ) );
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/wp-json/wp/v2/posts' ) ) ) );
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/wp-json/wp/v2/users-guide' ) ) ) );
	}

	public function test_logged_in_users_are_allowed(): void {
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/wp-json/wp/v2/users/me', 'logged_in' => true ) ) ) );
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'query' => array( 'author' => '1' ), 'logged_in' => true ) ) ) );
	}

	public function test_sub_options(): void {
		$this->assertNull( $this->rule( array( 'block_author_scan' => false ) )->inspect( Requests::make( array( 'query' => array( 'author' => '1' ) ) ) ) );
		$this->assertNull( $this->rule( array( 'block_rest_users' => false ) )->inspect( Requests::make( array( 'uri' => '/wp-json/wp/v2/users' ) ) ) );
	}

	/** @dataProvider author_probes */
	public function test_author_probes_that_wordpress_casts_to_an_id( $query ): void {
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'query' => $query ) ) ), json_encode( $query ) );
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'query' => $query, 'logged_in' => true ) ) ) );
	}

	public static function author_probes(): array {
		return array(
			array( array( 'author' => '1' ) ),
			array( array( 'author' => ' 1' ) ),
			array( array( 'author' => '+1' ) ),
			array( array( 'author' => '1abc' ) ),
			array( array( 'author' => '01' ) ),
			array( array( 'author' => '1.5' ) ),
			array( array( 'author' => '1e3' ) ),
			array( array( 'author' => array( '1' ) ) ),
			array( array( 'author_name' => 'admin' ) ),
			array( array( 'author_name' => 'a' ) ),
		);
	}

	/** @dataProvider harmless_author_values */
	public function test_values_that_resolve_to_no_author_pass( array $query ): void {
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'query' => $query ) ) ) );
	}

	public static function harmless_author_values(): array {
		return array(
			array( array( 'author' => '' ) ),
			array( array( 'author' => '0' ) ),
			array( array( 'author' => '-1' ) ),
			array( array( 'author' => 'jane' ) ),
			array( array( 'author_name' => '' ) ),
			array( array( 'author_name' => '  ' ) ),
			array( array( 's' => 'author' ) ),
		);
	}

	public function test_post_body_probes_are_scans_too(): void {
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'method' => 'POST', 'post' => array( 'author' => '1' ) ) ) ) );
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'method' => 'POST', 'post' => array( 'author_name' => 'admin' ) ) ) ) );
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'method' => 'POST', 'post' => array( 'rest_route' => '/wp/v2/users' ) ) ) ) );
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'method' => 'POST', 'post' => array( 'author' => '1' ), 'logged_in' => true ) ) ) );
	}

	public function test_a_fake_admin_path_gets_no_exemption(): void {
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/index.php/wp-admin/?author=1', 'query' => array( 'author' => '1' ) ) ) ) );
		$this->assertNotNull( $this->rule()->inspect( Requests::make( array( 'uri' => '/x/wp-admin/?author=1', 'query' => array( 'author' => '1' ) ) ) ) );
	}
}
