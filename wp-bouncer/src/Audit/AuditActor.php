<?php
/**
 * Who made a settings change.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Audit;

defined( 'ABSPATH' ) || exit;

/**
 * Pure PHP. The login is never request-derived; the caller passes the
 * WordPress user's login. "cli" and "unknown" mean "no authenticated WordPress
 * user", not "trusted".
 */
final class AuditActor {

	/** Longest login shown. */
	private const LOGIN_MAX = 60;

	/** Context flags, in priority order. */
	private const LABELS = array( 'upgrade', 'cli', 'cron', 'rest', 'ajax' );

	/**
	 * Build the actor text.
	 *
	 * @param string|null        $login Login of the current user, or null when nobody is signed in.
	 * @param array<string,bool> $ctx   Flags: upgrade, cli, cron, rest, ajax.
	 * @param int                $id    User ID (shown as "#ID" after the login so a look-alike login can't pass for another user).
	 * @return string Never empty.
	 */
	public static function resolve( ?string $login, array $ctx, int $id = 0 ): string {
		// Control and format characters (C0, C1, bidi, zero-width) can imitate another user or label.
		$has_user = null !== $login;
		$login    = null === $login ? '' : (string) preg_replace( '/[\p{Cc}\p{Cf}]/u', '', $login );
		$login    = trim( $login );
		if ( mb_strlen( $login ) > self::LOGIN_MAX ) {
			$login = mb_substr( $login, 0, self::LOGIN_MAX );
		}

		// The ID stays even when the stripped login is empty: it is what tells users apart.
		if ( $has_user && $id > 0 ) {
			$login = trim( $login . ' #' . $id );
		}

		$label = '';
		foreach ( self::LABELS as $flag ) {
			if ( ! empty( $ctx[ $flag ] ) ) {
				$label = $flag;
				break;
			}
		}

		if ( '' !== $login && '' !== $label ) {
			return $login . ' (' . $label . ')';
		}
		if ( '' !== $login ) {
			return $login;
		}
		return '' !== $label ? $label : 'unknown';
	}
}
