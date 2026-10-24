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
	<fieldset class="wpb-inline">
		<label><input type="checkbox" name="wp_bouncer[rules][waf][sqli]" value="1" <?php checked( $r['waf']['sqli'] ); ?>> <?php esc_html_e( 'SQL injection', 'wp-bouncer' ); ?></label>
		<label><input type="checkbox" name="wp_bouncer[rules][waf][xss]" value="1" <?php checked( $r['waf']['xss'] ); ?>> <?php esc_html_e( 'Cross-site scripting', 'wp-bouncer' ); ?></label>
		<label><input type="checkbox" name="wp_bouncer[rules][waf][traversal]" value="1" <?php checked( $r['waf']['traversal'] ); ?>> <?php esc_html_e( 'Path traversal / file inclusion', 'wp-bouncer' ); ?></label>
		<label><input type="checkbox" name="wp_bouncer[rules][waf][code_injection]" value="1" <?php checked( $r['waf']['code_injection'] ); ?>> <?php esc_html_e( 'PHP / command injection', 'wp-bouncer' ); ?></label>
	</fieldset>
	<p><label><input type="checkbox" name="wp_bouncer[rules][waf][inspect_json]" value="1" <?php checked( $r['waf']['inspect_json'] ); ?>> <?php esc_html_e( 'Also inspect JSON request bodies', 'wp-bouncer' ); ?></label></p>
	<p class="description"><?php esc_html_e( 'Scans application/json and +json bodies (such as REST API requests) like form fields. Turn off if a plugin sends code in JSON.', 'wp-bouncer' ); ?></p>
	<p><label for="wpb-waf-excl"><?php esc_html_e( 'Parameter names to never inspect (one per line), for forms that legitimately submit code or HTML:', 'wp-bouncer' ); ?></label></p>
	<textarea id="wpb-waf-excl" name="wp_bouncer[rules][waf][excluded_params]" rows="3" class="large-text code"><?php echo esc_textarea( implode( "\n", $r['waf']['excluded_params'] ) ); ?></textarea>
	<p class="description"><?php esc_html_e( 'Administrators are never inspected.', 'wp-bouncer' ); ?></p>
