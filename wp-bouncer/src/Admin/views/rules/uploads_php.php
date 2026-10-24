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
use WPBouncer\Hardening\UploadsGuard;
use WPBouncer\Hardening\UploadsPolicy;

defined( 'ABSPATH' ) || exit;
?>
	<?php
	$wpb_present = UploadsGuard::block_present();
	$wpb_wanted  = $plugin->uploads_guard()->wants_htaccess();
	$wpb_probe   = get_option( UploadsGuard::PROBE_OPTION );
	$wpb_netcap  = current_user_can( AdminController::FIREWALL_CAPABILITY );
	?>
	<p class="description"><?php esc_html_e( 'The commonest way WordPress sites get backdoored: a weak upload form in some plugin lets an attacker put a .php file in wp-content/uploads, then they run it by visiting its address.', 'wp-bouncer' ); ?></p>
	<label><input type="checkbox" name="wp_bouncer[rules][uploads_php][htaccess]" value="1" <?php checked( $r['uploads_php']['htaccess'] ); ?> <?php disabled( ! $wpb_netcap ); ?>> <?php esc_html_e( 'Tell the web server not to run scripts in the uploads folder (writes a marked block to wp-content/uploads/.htaccess; works on Apache and LiteSpeed)', 'wp-bouncer' ); ?></label>
	<?php if ( ! $wpb_netcap ) : ?>
		<span class="description"><?php esc_html_e( 'Managed by your network administrator.', 'wp-bouncer' ); ?></span>
	<?php endif; ?><br>
	<label><input type="checkbox" name="wp_bouncer[rules][uploads_php][check_uploads]" value="1" <?php checked( $r['uploads_php']['check_uploads'] ); ?>> <?php esc_html_e( 'Refuse uploads through WordPress that are scripts in disguise (such as photo.php.jpg, .phtml, .htaccess, or an "image" containing PHP code)', 'wp-bouncer' ); ?></label>

	<div class="wpb-uploads-status">
		<p>
			<strong><?php esc_html_e( '.htaccess block:', 'wp-bouncer' ); ?></strong>
			<?php
			if ( $wpb_present ) {
				esc_html_e( 'in place.', 'wp-bouncer' );
			} elseif ( $wpb_wanted && UploadsGuard::is_broken() ) {
				echo '<span class="wpb-warn">' . esc_html__( 'removed, because your server answered uploaded files with an error while it was there.', 'wp-bouncer' ) . '</span>';
			} elseif ( $wpb_wanted ) {
				echo '<span class="wpb-warn">' . esc_html__( 'missing. It may have been removed, or the folder is not writable.', 'wp-bouncer' ) . '</span>';
			} else {
				esc_html_e( 'not used.', 'wp-bouncer' );
			}
			?>
			<?php if ( $wpb_netcap && $wpb_wanted !== $wpb_present ) : ?>
				<button type="submit" class="button button-small" form="wpb-uploads-sync-form"><?php echo $wpb_wanted ? esc_html__( 'Write it now', 'wp-bouncer' ) : esc_html__( 'Remove it now', 'wp-bouncer' ); ?></button>
			<?php endif; ?>
		</p>
		<p>
			<strong><?php esc_html_e( 'Server test:', 'wp-bouncer' ); ?></strong>
			<?php
			if ( is_array( $wpb_probe ) && ! empty( $wpb_probe['time'] ) ) {
				echo esc_html( AdminController::probe_message( (string) $wpb_probe['result'] ) );
				echo ' <span class="description">(' . esc_html( (string) $wpb_probe['detail'] ) . ', ' . esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $wpb_probe['time'] ) ) . ')</span>';
			} else {
				esc_html_e( 'not run yet.', 'wp-bouncer' );
			}
			?>
			<?php if ( $wpb_netcap ) : ?>
				<button type="submit" class="button button-small" form="wpb-uploads-probe-form"><?php esc_html_e( 'Test now', 'wp-bouncer' ); ?></button>
			<?php endif; ?>
		</p>
		<p class="description"><?php esc_html_e( 'The test puts a tiny script in the uploads folder, asks your server for it, and deletes it.', 'wp-bouncer' ); ?></p>
		<details>
			<summary><?php esc_html_e( 'Using nginx? It ignores .htaccess. Add this to your server block:', 'wp-bouncer' ); ?></summary>
			<pre class="wpb-code"><?php echo esc_html( UploadsPolicy::nginx_snippet() ); ?></pre>
		</details>
	</div>
