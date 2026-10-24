<?php
/**
 * Stops anonymous visitors from harvesting usernames.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;

defined( 'ABSPATH' ) || exit;

/**
 * Attackers find valid usernames before brute-forcing passwords. The two
 * classic leaks are /?author=1 (which redirects to /author/<username>/) and
 * the REST endpoint /wp-json/wp/v2/users.
 *
 * Settings:
 * - enabled (bool)
 * - block_author_scan (bool): refuse ?author=N for logged-out visitors.
 * - block_rest_users (bool): refuse /wp/v2/users for logged-out visitors.
 *
 * Plugin.php also removes the users sitemap while this rule is on.
 */
final class UserEnumerationRule extends AbstractRule {

	public const ID = 'user_enumeration';

	/** {@inheritDoc} */
	public function id(): string {
		return self::ID;
	}

	/**
	 * Inspect the request.
	 *
	 * @param Request $request Incoming request.
	 * @return Verdict|null A Verdict to refuse the request, or null to let it through.
	 */
	public function inspect( Request $request ): ?Verdict {
		$query = $request->query();

		$is_author_scan = $this->setting( 'block_author_scan', true )
			&& ( self::is_author_probe( $query ) || self::is_author_probe( $request->post() ) )
			&& ! $request->is_admin_area();

		$route         = $request->rest_route();
		$is_rest_users = $this->setting( 'block_rest_users', true )
			&& '' !== $route
			&& 1 === preg_match( '#^/wp/v2/users(/|$)#', $route );

		if ( ! $is_author_scan && ! $is_rest_users ) {
			return null;
		}

		// Checked last so the (lazy) login lookup only runs for suspicious requests.
		if ( $request->is_logged_in() ) {
			return null;
		}

		return $this->deny( $is_author_scan ? 'Author scan (?author=N or ?author_name=)' : 'REST API user listing' );
	}

	/**
	 * Does the query string ask WordPress to resolve an author?
	 *
	 * WordPress reads a leading integer from "author" ("1abc" is author 1) and
	 * redirects /?author_name=x to the author archive, so both leak usernames.
	 *
	 * @param array<mixed> $query Query-string parameters.
	 */
	private static function is_author_probe( array $query ): bool {
		if ( isset( $query['author'] ) ) {
			$author = $query['author'];
			if ( is_array( $author ) ) {
				return array() !== $author;
			}
			if ( is_scalar( $author ) && (int) $author > 0 ) {
				return true;
			}
		}
		if ( isset( $query['author_name'] ) ) {
			$name = $query['author_name'];
			if ( is_array( $name ) ) {
				return array() !== $name;
			}
			return is_scalar( $name ) && '' !== trim( (string) $name );
		}
		return false;
	}
}
