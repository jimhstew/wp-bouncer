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
	<label><input type="checkbox" name="wp_bouncer[rules][user_enumeration][block_author_scan]" value="1" <?php checked( $r['user_enumeration']['block_author_scan'] ); ?>> <?php esc_html_e( 'Block ?author=N scans', 'wp-bouncer' ); ?></label><br>
	<label><input type="checkbox" name="wp_bouncer[rules][user_enumeration][block_rest_users]" value="1" <?php checked( $r['user_enumeration']['block_rest_users'] ); ?>> <?php esc_html_e( 'Block the REST API user list (/wp-json/wp/v2/users) for logged-out visitors', 'wp-bouncer' ); ?></label>
	<p class="description"><?php esc_html_e( 'The users sitemap is also removed while this rule is on.', 'wp-bouncer' ); ?></p>
