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
			/* translators: 1: attempts input, 2: window input, 3: lockout input. */
			esc_html__( 'Lock out an IP after %1$s failed logins within %2$s minutes, for %3$s minutes.', 'wp-bouncer' ),
			'<input type="number" min="1" max="100" class="small-text" name="wp_bouncer[rules][login_lockout][max_attempts]" value="' . esc_attr( (string) $r['login_lockout']['max_attempts'] ) . '" aria-label="' . esc_attr__( 'Attempts', 'wp-bouncer' ) . '">',
			'<input type="number" min="1" max="1440" class="small-text" name="wp_bouncer[rules][login_lockout][window_minutes]" value="' . esc_attr( (string) $r['login_lockout']['window_minutes'] ) . '" aria-label="' . esc_attr__( 'Window in minutes', 'wp-bouncer' ) . '">',
			'<input type="number" min="1" max="1440" class="small-text" name="wp_bouncer[rules][login_lockout][lockout_minutes]" value="' . esc_attr( (string) $r['login_lockout']['lockout_minutes'] ) . '" aria-label="' . esc_attr__( 'Lockout in minutes', 'wp-bouncer' ) . '">'
		); // phpcs:ignore WordPress.Security.EscapeOutput -- inputs escaped above.
		?>
	</p>
	<label for="wpb-banned-users"><?php esc_html_e( 'Usernames that cause an immediate lockout (one per line):', 'wp-bouncer' ); ?></label>
	<textarea id="wpb-banned-users" name="wp_bouncer[rules][login_lockout][banned_usernames]" rows="3" class="large-text code"><?php echo esc_textarea( implode( "\n", $r['login_lockout']['banned_usernames'] ) ); ?></textarea>
	<p class="description"><?php esc_html_e( 'Don\'t list a username that a real account on this site uses.', 'wp-bouncer' ); ?></p>
	<label><input type="checkbox" name="wp_bouncer[rules][login_lockout][generic_errors]" value="1" <?php checked( $r['login_lockout']['generic_errors'] ); ?>> <?php esc_html_e( 'Show one generic error for a wrong username or a wrong password, so attackers can\'t tell which usernames exist.', 'wp-bouncer' ); ?></label>
