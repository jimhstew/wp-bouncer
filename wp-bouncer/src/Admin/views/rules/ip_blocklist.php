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
	<label for="wpb-ips"><?php esc_html_e( 'Blocked IPs and ranges (one per line):', 'wp-bouncer' ); ?></label>
	<textarea id="wpb-ips" name="wp_bouncer[rules][ip_blocklist][ips]" rows="6" class="large-text code" placeholder="203.0.113.7&#10;198.51.100.0/24&#10;2001:db8::/32"><?php echo esc_textarea( implode( "\n", $r['ip_blocklist']['ips'] ) ); ?></textarea>
