<?php
/**
 * Countries tab: choose which countries to block (or admit).
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin    $plugin
 * @var array<string, mixed> $settings
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Geo\Countries;

defined( 'ABSPATH' ) || exit;

$rule     = $settings['rules']['country'];
$selected = array_flip( $rule['countries'] );
$meta     = get_option( \WPBouncer\Plugin::GEO_META_OPTION, array() );
$your_cc  = $plugin->geo()->lookup( $plugin->client_ip() );

// Group countries by continent for the picker.
$groups = array();
foreach ( Countries::all() as $code => $name ) {
	$continent              = Countries::continent( $code );
	$groups[ $continent ][] = array( $code, $name );
}
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="wpb-countries-form">
	<?php wp_nonce_field( 'wp_bouncer_save' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_save">
	<input type="hidden" name="tab" value="countries">

	<section class="wpb-card wpb-rule">
		<div class="wpb-rule-head">
			<?php AdminController::rule_switch( 'country', ! empty( $rule['enabled'] ), false, __( 'Country blocking', 'wp-bouncer' ) ); ?>
			<div>
				<h2><?php esc_html_e( 'Country blocking', 'wp-bouncer' ); ?></h2>
				<p class="description">
					<?php
					if ( ! empty( $meta['rows'] ) ) {
						/* translators: %s: number of IP ranges. */
						printf( esc_html__( 'Geo database: %s IP ranges loaded.', 'wp-bouncer' ), esc_html( number_format_i18n( (int) $meta['rows'] ) ) );
					} else {
						printf(
							/* translators: %s: link to Tools tab. */
							esc_html__( 'No geo database loaded yet. %s', 'wp-bouncer' ),
							'<a href="' . esc_url( AdminController::url( 'tools' ) ) . '">' . esc_html__( 'Import one under Tools.', 'wp-bouncer' ) . '</a>'
						);
					}
					if ( $your_cc ) {
						echo ' ';
						/* translators: %s: country name. */
						printf( esc_html__( 'You appear to be in %s.', 'wp-bouncer' ), '<strong>' . esc_html( Countries::name( $your_cc ) ) . '</strong>' );
					}
					?>
				</p>
			</div>
		</div>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Mode', 'wp-bouncer' ); ?></th>
				<td>
					<label><input type="radio" name="wp_bouncer[rules][country][mode]" value="block" <?php checked( $rule['mode'], 'block' ); ?>> <?php esc_html_e( 'Block the selected countries', 'wp-bouncer' ); ?></label><br>
					<label><input type="radio" name="wp_bouncer[rules][country][mode]" value="allow" <?php checked( $rule['mode'], 'allow' ); ?>> <?php esc_html_e( 'Only allow the selected countries (block all others)', 'wp-bouncer' ); ?></label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Apply to', 'wp-bouncer' ); ?></th>
				<td>
					<label><input type="radio" name="wp_bouncer[rules][country][scope]" value="site" <?php checked( $rule['scope'], 'site' ); ?>> <?php esc_html_e( 'The whole site', 'wp-bouncer' ); ?></label><br>
					<label><input type="radio" name="wp_bouncer[rules][country][scope]" value="login" <?php checked( $rule['scope'], 'login' ); ?>> <?php esc_html_e( 'Only login, XML-RPC and wp-admin (visitors can still read the site)', 'wp-bouncer' ); ?></label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Unknown location', 'wp-bouncer' ); ?></th>
				<td><label><input type="checkbox" name="wp_bouncer[rules][country][block_unknown]" value="1" <?php checked( $rule['block_unknown'] ); ?>> <?php esc_html_e( 'Also block IPs whose country can\'t be determined', 'wp-bouncer' ); ?></label></td>
			</tr>
		</table>
	</section>

	<section class="wpb-card">
		<div class="wpb-country-toolbar">
			<label class="screen-reader-text" for="wpb-country-filter"><?php esc_html_e( 'Filter countries', 'wp-bouncer' ); ?></label>
			<input type="search" id="wpb-country-filter" class="regular-text" placeholder="<?php esc_attr_e( 'Filter countries…', 'wp-bouncer' ); ?>">
			<button type="button" class="button" data-wpb-select="visible"><?php esc_html_e( 'Select shown', 'wp-bouncer' ); ?></button>
			<button type="button" class="button" data-wpb-select="none"><?php esc_html_e( 'Clear all', 'wp-bouncer' ); ?></button>
			<strong class="wpb-country-count" aria-live="polite"></strong>
		</div>

		<?php foreach ( $groups as $continent => $countries ) : ?>
			<fieldset class="wpb-continent">
				<legend>
					<?php echo esc_html( '' === $continent ? __( 'Special', 'wp-bouncer' ) : Countries::CONTINENTS[ $continent ] ); ?>
					<button type="button" class="button-link" data-wpb-continent><?php esc_html_e( 'toggle all', 'wp-bouncer' ); ?></button>
				</legend>
				<div class="wpb-country-grid">
					<?php foreach ( $countries as list( $code, $name ) ) : ?>
						<label class="wpb-country" data-name="<?php echo esc_attr( strtolower( $name . ' ' . $code ) ); ?>">
							<input type="checkbox" name="wp_bouncer[rules][country][countries][]" value="<?php echo esc_attr( $code ); ?>" <?php checked( isset( $selected[ $code ] ) ); ?>>
							<span class="wpb-flag" aria-hidden="true"><?php echo esc_html( AdminController::flag( $code ) ); ?></span>
							<?php echo esc_html( $name ); ?>
							<code><?php echo esc_html( $code ); ?></code>
						</label>
					<?php endforeach; ?>
				</div>
			</fieldset>
		<?php endforeach; ?>
	</section>

	<?php submit_button(); ?>
</form>
