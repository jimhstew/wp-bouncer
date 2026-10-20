<?php
/**
 * Page title and tab navigation.
 *
 * @package WPBouncer
 * @var string $tab Current tab.
 */

use WPBouncer\Admin\AdminController;

defined( 'ABSPATH' ) || exit;
?>
<h1 class="wpb-title">
	<span class="dashicons dashicons-shield" aria-hidden="true"></span>
	<?php esc_html_e( 'WP Bouncer', 'wp-bouncer' ); ?>
</h1>
<nav class="nav-tab-wrapper wp-clearfix" aria-label="<?php esc_attr_e( 'Bouncer sections', 'wp-bouncer' ); ?>">
	<?php foreach ( AdminController::tabs() as $key => $label ) : ?>
		<a href="<?php echo esc_url( AdminController::url( $key ) ); ?>" class="nav-tab <?php echo $tab === $key ? 'nav-tab-active' : ''; ?>" <?php echo $tab === $key ? 'aria-current="page"' : ''; ?>>
			<?php echo esc_html( $label ); ?>
		</a>
	<?php endforeach; ?>
</nav>
