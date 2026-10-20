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

	/** {@inheritDoc} */
	public function inspect( Request $request ): ?Verdict {
		$query = $request->query();

		$is_author_scan = $this->setting( 'block_author_scan', true )
			&& isset( $query['author'] )
			&& is_scalar( $query['author'] )
			&& preg_match( '/^\s*-?\d+/', (string) $query['author'] )
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

		return $this->deny( $is_author_scan ? 'Author ID scan (?author=N)' : 'REST API user listing' );
	}
}
