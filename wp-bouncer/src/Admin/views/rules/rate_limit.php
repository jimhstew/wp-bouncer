<?php
/**
 * Rules tab: the settings of one rule, inside its "Settings" disclosure.
 *
 * Moved from the old single-page Rules tab with its field names unchanged. Every input here is
 * always rendered and submitted, even while the disclosure is closed: Settings::apply_form()
 * treats a rule missing from the POST as switched off.
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin    $plugin
 * @var array<string, mixed> $r      Settings: the rules array.
 */

defined( 'ABSPATH' ) || exit;
?>
	<p>
		<?php
		printf(
			/* translators: 1: requests input, 2: seconds input, 3: ban input. */
			esc_html__( 'Ban an IP that makes more than %1$s requests in %2$s seconds, for %3$s minutes.', 'wp-bouncer' ),
			'<input type="number" min="10" max="100000" class="small-text" name="wp_bouncer[rules][rate_limit][max_requests]" value="' . esc_attr( (string) $r['rate_limit']['max_requests'] ) . '" aria-label="' . esc_attr__( 'Requests', 'wp-bouncer' ) . '">',
			'<input type="number" min="1" max="3600" class="small-text" name="wp_bouncer[rules][rate_limit][window_seconds]" value="' . esc_attr( (string) $r['rate_limit']['window_seconds'] ) . '" aria-label="' . esc_attr__( 'Seconds', 'wp-bouncer' ) . '">',
			'<input type="number" min="1" max="1440" class="small-text" name="wp_bouncer[rules][rate_limit][ban_minutes]" value="' . esc_attr( (string) $r['rate_limit']['ban_minutes'] ) . '" aria-label="' . esc_attr__( 'Ban minutes', 'wp-bouncer' ) . '">'
		); // phpcs:ignore WordPress.Security.EscapeOutput -- inputs escaped above.
		?>
	</p>
	<p class="description"><?php esc_html_e( 'Only requests handled by WordPress count; images, CSS and JS served by the web server do not. Without a persistent object cache (Redis/Memcached) each counted request writes to the database, so leave this off on busy sites without one.', 'wp-bouncer' ); ?></p>
