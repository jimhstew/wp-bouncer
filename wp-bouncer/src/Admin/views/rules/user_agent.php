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

use WPBouncer\Admin\AdminController;
use WPBouncer\Rules\UserAgentRule;

defined( 'ABSPATH' ) || exit;
?>
	<label><input type="checkbox" name="wp_bouncer[rules][user_agent][block_empty]" value="1" <?php checked( $r['user_agent']['block_empty'] ); ?>> <?php esc_html_e( 'Block requests that send no User-Agent at all', 'wp-bouncer' ); ?></label>
	<p><label for="wpb-ua"><?php esc_html_e( 'Blocked User-Agent patterns (one per line). Plain text matches anywhere, ignoring case. Wrap in slashes for a regular expression, e.g. /^curl\//i', 'wp-bouncer' ); ?></label></p>
	<textarea id="wpb-ua" name="wp_bouncer[rules][user_agent][patterns]" rows="8" class="large-text code"><?php echo esc_textarea( implode( "\n", $r['user_agent']['patterns'] ) ); ?></textarea>
	<?php if ( ! current_user_can( AdminController::FIREWALL_CAPABILITY ) ) : ?>
		<p class="description"><?php esc_html_e( 'Regular expressions (wrapped in slashes) can only be added by your network administrator. Existing ones are kept.', 'wp-bouncer' ); ?></p>
	<?php endif; ?>
	<?php
	// Patterns that failed to run (for example by backtracking too much) in the last hour; they match nothing until fixed.
	foreach ( array_slice( (array) $r['user_agent']['patterns'], 0, UserAgentRule::MAX_PATTERNS ) as $wpb_pattern ) {
		if ( null !== $plugin->store()->get( 'pcre_error:ua:' . md5( (string) $wpb_pattern ) ) ) {
			echo '<p class="notice notice-warning inline" role="alert"><strong>' . esc_html__( 'This pattern failed to run and is being ignored:', 'wp-bouncer' ) . '</strong> <code>' . esc_html( (string) $wpb_pattern ) . '</code> ' . esc_html__( 'It may be invalid or too slow. Simplify it, or use plain text.', 'wp-bouncer' ) . '</p>';
		}
	}
	if ( count( (array) $r['user_agent']['patterns'] ) > UserAgentRule::MAX_PATTERNS ) {
		echo '<p class="notice notice-warning inline" role="alert">' . esc_html(
			sprintf(
				/* translators: %d: maximum number of patterns. */
				__( 'Only the first %d patterns are used.', 'wp-bouncer' ),
				UserAgentRule::MAX_PATTERNS
			)
		) . '</p>';
	}
	?>
