<?php
/**
 * General tab: mode, IP detection, allowlist, logging, geo source.
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin    $plugin
 * @var array<string, mixed> $settings
 */

defined( 'ABSPATH' ) || exit;

$your_ip = $plugin->client_ip();
?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'wp_bouncer_save' ); ?>
	<input type="hidden" name="action" value="wp_bouncer_save">
	<input type="hidden" name="tab" value="general">

	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Mode', 'wp-bouncer' ); ?></th>
			<td>
				<fieldset>
					<label><input type="radio" name="wp_bouncer[mode]" value="enforce" <?php checked( $settings['mode'], 'enforce' ); ?>> <strong><?php esc_html_e( 'Enforce', 'wp-bouncer' ); ?></strong>: <?php esc_html_e( 'block matching requests.', 'wp-bouncer' ); ?></label><br>
					<label><input type="radio" name="wp_bouncer[mode]" value="monitor" <?php checked( $settings['mode'], 'monitor' ); ?>> <strong><?php esc_html_e( 'Monitor', 'wp-bouncer' ); ?></strong>: <?php esc_html_e( 'only log what would have been blocked. Use this for a few days after setup to check for false positives.', 'wp-bouncer' ); ?></label>
				</fieldset>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-ip-source"><?php esc_html_e( 'Client IP source', 'wp-bouncer' ); ?></label></th>
			<td>
				<select id="wpb-ip-source" name="wp_bouncer[ip_source]">
					<?php
					$sources = array(
						'remote_addr'      => __( 'REMOTE_ADDR (direct connection, the default)', 'wp-bouncer' ),
						'x_forwarded_for'  => __( 'X-Forwarded-For (load balancer / reverse proxy)', 'wp-bouncer' ),
						'cf_connecting_ip' => __( 'CF-Connecting-IP (Cloudflare)', 'wp-bouncer' ),
						'x_real_ip'        => __( 'X-Real-IP (nginx proxy)', 'wp-bouncer' ),
					);
					foreach ( $sources as $value => $label ) {
						printf( '<option value="%s" %s>%s</option>', esc_attr( $value ), selected( $settings['ip_source'], $value, false ), esc_html( $label ) );
					}
					?>
				</select>
				<p class="description">
					<?php
					/* translators: %s: detected IP address. */
					printf( esc_html__( 'Your IP as currently detected: %s. If this shows your proxy\'s address instead of yours, change the source.', 'wp-bouncer' ), '<code>' . esc_html( $your_ip ?: '?' ) . '</code>' );
					?>
				</p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-proxies"><?php esc_html_e( 'Trusted proxies', 'wp-bouncer' ); ?></label></th>
			<td>
				<textarea id="wpb-proxies" name="wp_bouncer[trusted_proxies]" rows="4" class="large-text code" placeholder="173.245.48.0/20"><?php echo esc_textarea( implode( "\n", $settings['trusted_proxies'] ) ); ?></textarea>
				<p class="description"><?php esc_html_e( 'IPs or CIDR ranges of your proxy or CDN, one per line. The IP header above is only believed when the request comes from one of these.', 'wp-bouncer' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-allowlist"><?php esc_html_e( 'Allowlist', 'wp-bouncer' ); ?></label></th>
			<td>
				<textarea id="wpb-allowlist" name="wp_bouncer[allowlist]" rows="5" class="large-text code"><?php echo esc_textarea( implode( "\n", $settings['allowlist'] ) ); ?></textarea>
				<p class="description">
					<?php esc_html_e( 'IPs or CIDR ranges that skip every rule, one per line. Loopback addresses (WP-Cron, health checks) are always allowed.', 'wp-bouncer' ); ?>
					<?php if ( $your_ip ) : ?>
						<button type="button" class="button button-small" data-wpb-add-ip="#wpb-allowlist"><?php esc_html_e( 'Add my IP', 'wp-bouncer' ); ?></button>
					<?php endif; ?>
				</p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-retention"><?php esc_html_e( 'Keep log entries for', 'wp-bouncer' ); ?></label></th>
			<td>
				<input id="wpb-retention" type="number" min="1" max="365" name="wp_bouncer[log_retention_days]" value="<?php echo esc_attr( (string) $settings['log_retention_days'] ); ?>" class="small-text"> <?php esc_html_e( 'days', 'wp-bouncer' ); ?>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="wpb-message"><?php esc_html_e( 'Block page message', 'wp-bouncer' ); ?></label></th>
			<td>
				<textarea id="wpb-message" name="wp_bouncer[block_message]" rows="2" class="large-text"><?php echo esc_textarea( $settings['block_message'] ); ?></textarea>
				<p class="description"><?php esc_html_e( 'Plain text shown to blocked visitors, with a reference number that matches the log entry.', 'wp-bouncer' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Country lookup', 'wp-bouncer' ); ?></th>
			<td>
				<fieldset>
					<label><input type="radio" name="wp_bouncer[geo_source]" value="database" <?php checked( $settings['geo_source'], 'database' ); ?>> <?php esc_html_e( 'Local geo database (import one under Tools)', 'wp-bouncer' ); ?></label><br>
					<label><input type="radio" name="wp_bouncer[geo_source]" value="header" <?php checked( $settings['geo_source'], 'header' ); ?>> <?php esc_html_e( 'Header or server variable set by my CDN or web server, falling back to the local database', 'wp-bouncer' ); ?></label>
				</fieldset>
				<p>
					<label for="wpb-geo-header"><?php esc_html_e( 'Header / variable name:', 'wp-bouncer' ); ?></label>
					<input id="wpb-geo-header" type="text" name="wp_bouncer[geo_header]" value="<?php echo esc_attr( $settings['geo_header'] ); ?>" class="regular-text code">
				</p>
				<p class="description"><?php esc_html_e( 'For example CF-IPCountry (Cloudflare), GEOIP_COUNTRY_CODE (nginx/Apache GeoIP module) or MM_COUNTRY_CODE. Only use a header if visitors can\'t bypass the CDN to reach your server, since clients can forge headers.', 'wp-bouncer' ); ?></p>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>
