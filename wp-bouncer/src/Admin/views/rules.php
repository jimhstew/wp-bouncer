<?php
/**
 * Rules tab: rules grouped into categories on ONE form.
 *
 * Every rule input is always rendered and submitted (see partials/rule-row.php): closed
 * "Settings" panels still post, and Settings::apply_form() switches off any rule whose inputs
 * are missing from the POST.
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin               $plugin
 * @var array<string, mixed>            $settings
 * @var \WPBouncer\Admin\RuleOverview   $overview
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Admin\RuleCatalog;
use WPBouncer\Admin\RuleLabels;

defined( 'ABSPATH' ) || exit;

$r = $settings['rules'];

// The settings of one built-in rule open when a link names it (?wpb_rule=waf). Anything else is ignored.
// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- navigation only: the value only adds "open" to one panel.
$wpb_open = isset( $_GET['wpb_rule'] ) ? sanitize_key( wp_unslash( $_GET['wpb_rule'] ) ) : '';
if ( ! RuleCatalog::is_builtin( $wpb_open ) ) {
	$wpb_open = '';
}
$wpb_seq        = 0;
$wpb_categories = $overview->categories();
?>
<nav class="wpb-cat-nav" aria-label="<?php esc_attr_e( 'Rule categories', 'wp-bouncer' ); ?>">
	<ul>
		<?php foreach ( $wpb_categories as $wpb_category ) : ?>
			<li>
				<a href="#wpb-cat-<?php echo esc_attr( $wpb_category['slug'] ); ?>"><?php echo esc_html( $wpb_category['title'] ); ?></a>
				<span class="description">
					<?php
					echo esc_html( RuleLabels::summary( $wpb_category['on'], $wpb_category['total'] ) );
					if ( $wpb_category['attention'] > 0 ) {
						echo ' &middot; <strong class="wpb-warn">' . esc_html( RuleLabels::attention( $wpb_category['attention'] ) ) . '</strong>';
					}
					?>
				</span>
			</li>
		<?php endforeach; ?>
	</ul>
	<p class="wpb-expand" hidden>
		<button type="button" class="button button-small" data-wpb-expand="all"></button>
		<button type="button" class="button button-small" data-wpb-expand="none"></button>
	</p>
</nav>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpb-rules-form">
	<?php wp_nonce_field( 'wp_bouncer_save' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_save">
	<input type="hidden" name="tab" value="rules">

	<?php // The grid is a wrapper so the save bar stays outside it and can stick to the viewport. ?>
	<div class="wpb-rules-grid">
		<?php
		foreach ( $wpb_categories as $wpb_category ) {
			require __DIR__ . '/partials/rule-category.php';
		}
		?>
	</div>

	<div class="wpb-savebar">
		<?php submit_button(); ?>
		<span class="wpb-unsaved" role="status" aria-live="polite"></span>
	</div>
</form>

<?php // Targets of the buttons in the uploads panel (forms can't be nested). ?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="wpb-uploads-probe-form">
	<?php wp_nonce_field( 'wp_bouncer_uploads_probe' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_uploads_probe">
</form>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="wpb-uploads-sync-form">
	<?php wp_nonce_field( 'wp_bouncer_uploads_sync' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_uploads_sync">
</form>
