<?php
/**
 * Site-wide admin notices about IP detection.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Firewall\IpResolver;
use WPBouncer\Firewall\IpSetupAdvisor;
use WPBouncer\Plugin;
use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Shows what IpSetupAdvisor finds on every admin screen, to administrators only.
 *
 * These notices are deliberately not dismissible: a wrong IP setup either
 * leaves the firewall blind (every visitor looks like one proxy address) or
 * lets visitors pick their own IP. The buttons post to admin-post.php
 * (AdminController::handle_ip_setup()), which checks a nonce and the capability.
 */
final class SetupNotices {

	/** Nonce action shared with AdminController::handle_ip_setup(). */
	public const NONCE_ACTION = 'wp_bouncer_ip_setup';

	/**
	 * Plugin instance.
	 *
	 * @var Plugin
	 */
	private Plugin $plugin;

	/**
	 * Set up the SetupNotices.
	 *
	 * @param Plugin $plugin Plugin instance.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/** Register the hook. */
	public function register(): void {
		add_action( 'admin_notices', array( $this, 'render' ) );
	}

	/** Print the notices (admin_notices). */
	public function render(): void {
		if ( ! current_user_can( AdminController::CAPABILITY ) ) {
			return;
		}
		$settings = $this->plugin->settings();
		$findings = ( new IpSetupAdvisor() )->check(
			wp_unslash( $_SERVER ),
			(string) $settings->get( 'ip_source' ),
			(array) $settings->get( 'trusted_proxies' ),
			(array) $settings->get( 'allowlist' )
		);
		foreach ( $findings as $finding ) {
			$this->render_finding( $finding );
		}
	}

	/**
	 * Print one finding.
	 *
	 * @param array<string, mixed> $f Finding from IpSetupAdvisor.
	 */
	private function render_finding( array $f ): void {
		$peer = (string) ( $f['peer'] ?? '' );
		$link = sprintf( '<a href="%s">%s</a>', esc_url( AdminController::url( 'general' ) . '#wpb-proxies' ), esc_html__( 'General → Trusted proxies', 'wp-bouncer' ) );

		switch ( $f['code'] ?? '' ) {
			case IpSetupAdvisor::HEADER_WITHOUT_PROXIES:
				$source = (string) $f['source'];
				$text   = sprintf(
					/* translators: 1: header name, 2: IP address. */
					esc_html__( 'WP Bouncer is set to read visitor IPs from the %1$s header, but no trusted proxies are listed, so the header is being ignored. Every visitor now appears to come from the connection address %2$s. Until this is fixed, IP bans and login lockouts are suspended (login attempts are logged) and rate limiting is effectively off, so a shared proxy address is never banned.', 'wp-bouncer' ),
					'<code>' . esc_html( self::header_label( $source ) ) . '</code>',
					'<code>' . esc_html( $peer ) . '</code>'
				);
				$text  .= ' ' . ( ! empty( $f['header_present'] )
					? esc_html__( 'The header was present on this request, so a proxy is probably in front of the site.', 'wp-bouncer' )
					: esc_html__( 'The header was not present on this request, so there may be no proxy at all.', 'wp-bouncer' ) );
				$public = '' !== $peer && IpUtils::is_public( $peer );
				if ( $public ) {
					$text .= ' ' . esc_html__( 'The connection address is a public one, so it looks like a CDN or public proxy. Do not trust that single address: list the CDN\'s full published IP ranges under Trusted proxies.', 'wp-bouncer' );
				}
				$buttons  = ! $public && '' !== $peer && ! empty( $f['header_present'] ) ? $this->button( 'trust_peer', sprintf( /* translators: %s: IP address. */ __( 'Trust %s as my proxy', 'wp-bouncer' ), $peer ), $source, $peer ) : '';
				$buttons .= $this->button( 'use_remote_addr', __( 'I have no proxy: use the connection address', 'wp-bouncer' ), '', '', false );
				$this->notice( 'error', $text, $buttons, $link );
				break;

			case IpSetupAdvisor::LOOPBACK_PEER:
				$header = (string) $f['header'];
				$text   = sprintf(
					/* translators: %s: IP address. */
					esc_html__( 'This request reached WordPress from the local or private address %s with a forwarding header, so the site is probably behind a reverse proxy, but WP Bouncer is reading the connection address. Requests are no longer exempt just because they come from a loopback address, and every visitor looks like that one address.', 'wp-bouncer' ),
					'<code>' . esc_html( $peer ) . '</code>'
				);
				$buttons = '';
				if ( '' !== $header ) {
					$buttons = $this->button(
						'trust_peer',
						sprintf(
							/* translators: 1: header name, 2: IP address. */
							__( 'Read the IP from %1$s and trust %2$s', 'wp-bouncer' ),
							self::header_label( $header ),
							$peer
						),
						$header,
						$peer
					);
				}
				$this->notice( 'error', $text, $buttons, $link );
				break;

			case IpSetupAdvisor::BROAD_RANGES_IGNORED:
				$entries = array_map( 'esc_html', array_map( 'strval', (array) $f['entries'] ) );
				$text    = sprintf(
					/* translators: %s: list of IP ranges. */
					esc_html__( 'These trusted proxy or allowlist entries are too broad to be safe and are being ignored: %s. Saving the General settings removes them.', 'wp-bouncer' ),
					'<code>' . implode( '</code>, <code>', $entries ) . '</code>'
				);
				$this->notice( 'error', $text, '', $link );
				break;

			case IpSetupAdvisor::PEER_NOT_IN_PROXIES:
				$text = sprintf(
					/* translators: %s: IP address. */
					esc_html__( 'A request arrived with an IP header from %s, which is not on your trusted proxies list, so the header was ignored. If your proxy or CDN changed its address, add the new one.', 'wp-bouncer' ),
					'<code>' . esc_html( $peer ) . '</code>'
				);
				$this->notice( 'warning', $text, '', $link );
				break;
		}
	}

	/**
	 * A one-button form that posts to AdminController::handle_ip_setup().
	 *
	 * @param string $fix     trust_peer or use_remote_addr.
	 * @param string $label   Button text.
	 * @param string $header  ip_source key to read the IP from ('' keeps the current one).
	 * @param string $peer    The connection address the notice is about; the handler refuses it if it has changed.
	 * @param bool   $primary Style as the primary button.
	 * @return string HTML, escaped.
	 */
	private function button( string $fix, string $label, string $header, string $peer, bool $primary = true ): string {
		return sprintf(
			'<form method="post" action="%1$s" style="display:inline-block;margin:0 8px 0 0;"><input type="hidden" name="_wpnonce" value="%4$s">%5$s<input type="hidden" name="action" value="wp_bouncer_ip_setup"><input type="hidden" name="fix" value="%2$s"><input type="hidden" name="header" value="%3$s"><input type="hidden" name="peer" value="%8$s"><button type="submit" class="button %6$s">%7$s</button></form>',
			esc_url( admin_url( 'admin-post.php' ) ),
			esc_attr( $fix ),
			esc_attr( $header ),
			esc_attr( wp_create_nonce( self::NONCE_ACTION ) ),
			wp_referer_field( false ),
			$primary ? 'button-primary' : '',
			esc_html( $label ),
			esc_attr( $peer )
		);
	}

	/**
	 * Print a notice that can't be dismissed.
	 *
	 * @param string $type    error|warning.
	 * @param string $html    Message, already escaped.
	 * @param string $buttons Button forms, already escaped.
	 * @param string $link    Link, already escaped.
	 */
	private function notice( string $type, string $html, string $buttons, string $link ): void {
		$allowed = array(
			'code' => array(),
			'a'    => array( 'href' => array() ),
		);
		printf(
			'<div class="notice notice-%1$s wpb-ip-setup" role="alert"><p><strong>WP Bouncer:</strong> %2$s</p><div>%3$s %4$s</div></div>',
			esc_attr( $type ),
			wp_kses( $html, $allowed ),
			$buttons, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built by button() from escaped parts only.
			wp_kses( $link, $allowed )
		);
	}

	/**
	 * Display name of an ip_source.
	 *
	 * @param string $source IpResolver::SOURCES key.
	 */
	private static function header_label( string $source ): string {
		$labels = array(
			'x_forwarded_for'  => 'X-Forwarded-For',
			'cf_connecting_ip' => 'CF-Connecting-IP',
			'x_real_ip'        => 'X-Real-IP',
		);
		return $labels[ $source ] ?? ( IpResolver::SOURCES[ $source ] ?? $source );
	}
}
