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
	<p class="description"><?php esc_html_e( 'Requests for files such as /.env, /.git/config, wp-config.php.bak, backup.zip, dump.sql, debug.log, phpinfo.php, adminer.php or a known web shell. A file that exists is served by your web server before WordPress runs, so a request like this that reaches WordPress is someone guessing. No real visitor asks for them.', 'wp-bouncer' ); ?></p>
	<p>
		<?php
		printf(
			/* translators: %s: minutes input. */
			esc_html__( 'Ban the IP from the whole site for %s minutes (0 refuses only the probe itself).', 'wp-bouncer' ),
			'<input type="number" min="0" max="1440" class="small-text" name="wp_bouncer[rules][sensitive_files][ban_minutes]" value="' . esc_attr( (string) $r['sensitive_files']['ban_minutes'] ) . '" aria-label="' . esc_attr__( 'Ban minutes', 'wp-bouncer' ) . '">'
		); // phpcs:ignore WordPress.Security.EscapeOutput -- input escaped above.
		?>
	</p>
	<label for="wpb-sf-extra"><?php esc_html_e( 'More paths to treat as probes (one per line; matches anywhere in the path, ignoring case), e.g. /old-site/:', 'wp-bouncer' ); ?></label>
	<textarea id="wpb-sf-extra" name="wp_bouncer[rules][sensitive_files][extra_paths]" rows="3" class="large-text code"><?php echo esc_textarea( implode( "\n", $r['sensitive_files']['extra_paths'] ) ); ?></textarea>
	<p class="description"><?php esc_html_e( 'Logged-in administrators are never banned. /.well-known/ is never treated as a probe.', 'wp-bouncer' ); ?></p>
