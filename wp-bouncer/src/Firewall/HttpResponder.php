<?php
/**
 * Sends a minimal block page and stops WordPress.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Firewall;

defined( 'ABSPATH' ) || exit;

/**
 * Production responder: status code, no-cache headers, tiny HTML page, exit.
 *
 * The page deliberately doesn't name the rule that matched, so attackers
 * can't use it to probe the configuration.
 */
final class HttpResponder implements ResponderInterface {

	/**
	 * Refuse the request. Ends the request.
	 *
	 * @param Verdict $verdict   Why the request is refused.
	 * @param string  $message   Message shown to the visitor.
	 * @param int     $reference Log row id shown as a support reference (0 = none).
	 */
	public function deny( Verdict $verdict, string $message, int $reference ): void {
		if ( ! headers_sent() ) {
			http_response_code( $verdict->status() );
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			header( 'X-Robots-Tag: noindex, nofollow' );
			if ( $verdict->retry_after() > 0 ) {
				header( 'Retry-After: ' . $verdict->retry_after() );
			}
		}

		$title = 429 === $verdict->status() ? 'Too Many Requests' : 'Access Denied';
		$ref   = $reference > 0 ? '<p class="ref">Reference: ' . (int) $reference . '</p>' : '';

		echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
			. '<meta name="robots" content="noindex,nofollow"><title>' . htmlspecialchars( $title, ENT_QUOTES, 'UTF-8' ) . '</title>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped with htmlspecialchars( ENT_QUOTES, UTF-8 ); esc_html() is not used so the output stays byte-identical.
			. '<style>body{font:16px/1.5 system-ui,sans-serif;background:#f6f7f7;color:#1d2327;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}'
			. 'main{background:#fff;padding:2rem 2.5rem;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);max-width:32rem;margin:1rem}'
			. 'h1{margin-top:0;font-size:1.4rem}.ref{color:#646970;font-size:.85rem}</style></head><body><main>'
			. '<h1>' . htmlspecialchars( $title, ENT_QUOTES, 'UTF-8' ) . '</h1>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped with htmlspecialchars( ENT_QUOTES, UTF-8 ); esc_html() is not used so the output stays byte-identical.
			. '<p>' . htmlspecialchars( $message, ENT_QUOTES, 'UTF-8' ) . '</p>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped with htmlspecialchars( ENT_QUOTES, UTF-8 ); esc_html() is not used so the output stays byte-identical.
			. $ref // phpcs:ignore WordPress.Security.EscapeOutput -- integer cast above.
			. '</main></body></html>';
		exit;
	}
}
