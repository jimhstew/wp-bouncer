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
		$this->assertNull( $this->rule()->inspect( Requests::make( array( 'query' => array( 'author' => array( '1' ) ) ) ) ) );
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
}
