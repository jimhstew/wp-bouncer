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
			/* translators: 1: count input, 2: seconds input, 3: ban input. */
			esc_html__( 'Ban an IP that gets more than %1$s "not found" pages in %2$s seconds, for %3$s minutes.', 'wp-bouncer' ),
			'<input type="number" min="3" max="10000" class="small-text" name="wp_bouncer[rules][not_found][max_404]" value="' . esc_attr( (string) $r['not_found']['max_404'] ) . '" aria-label="' . esc_attr__( 'Not found pages', 'wp-bouncer' ) . '">',
			'<input type="number" min="10" max="3600" class="small-text" name="wp_bouncer[rules][not_found][window_seconds]" value="' . esc_attr( (string) $r['not_found']['window_seconds'] ) . '" aria-label="' . esc_attr__( 'Seconds', 'wp-bouncer' ) . '">',
			'<input type="number" min="1" max="1440" class="small-text" name="wp_bouncer[rules][not_found][ban_minutes]" value="' . esc_attr( (string) $r['not_found']['ban_minutes'] ) . '" aria-label="' . esc_attr__( 'Ban minutes', 'wp-bouncer' ) . '">'
		); // phpcs:ignore WordPress.Security.EscapeOutput -- inputs escaped above.
		?>
	</p>
	<label><input type="checkbox" name="wp_bouncer[rules][not_found][ignore_crawlers]" value="1" <?php checked( $r['not_found']['ignore_crawlers'] ); ?>> <?php esc_html_e( 'Don\'t count search engine crawlers (Google, Bing and others, by User-Agent), which often revisit pages that have been removed', 'wp-bouncer' ); ?></label>
	<p class="description"><?php esc_html_e( 'Missing images, CSS, JavaScript and fonts are not counted, so a page with a broken image never bans its reader. Logged-in administrators are not counted.', 'wp-bouncer' ); ?></p>
