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
	<fieldset>
		<label><input type="radio" name="wp_bouncer[rules][xmlrpc][mode]" value="block_all" <?php checked( $r['xmlrpc']['mode'], 'block_all' ); ?>> <?php esc_html_e( 'Block all XML-RPC requests (recommended unless you use an app or service that needs it)', 'wp-bouncer' ); ?></label><br>
		<label><input type="radio" name="wp_bouncer[rules][xmlrpc][mode]" value="block_abuse" <?php checked( $r['xmlrpc']['mode'], 'block_abuse' ); ?>> <?php esc_html_e( 'Allow XML-RPC, but block system.multicall (mass password guessing) and pingbacks (DDoS reflection)', 'wp-bouncer' ); ?></label>
	</fieldset>
