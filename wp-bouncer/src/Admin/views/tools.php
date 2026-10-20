<?php
/**
 * Tools tab: geo database import and unlocking IPs.
 *
 * @package WPBouncer
 * @var \WPBouncer\Plugin $plugin
 */

defined( 'ABSPATH' ) || exit;

$meta        = get_option( \WPBouncer\Plugin::GEO_META_OPTION, array() );
$running     = $plugin->geo_import()->status();
$default_url = 'https://download.db-ip.com/free/dbip-country-lite-' . gmdate( 'Y-m' ) . '.csv.gz';
?>
<section class="wpb-card">
	<h2><?php esc_html_e( 'Geo database', 'wp-bouncer' ); ?></h2>
	<?php if ( null !== $running ) : ?>
		<?php $percent = \WPBouncer\Geo\GeoImport::percent( $running ); ?>
		<div id="wpb-geo-progress" class="wpb-geo-progress">
			<p>
				<?php
				printf(
					/* translators: %s: file name or URL. */
					esc_html__( 'Importing %s. Keep this page open until it finishes.', 'wp-bouncer' ),
					'<code>' . esc_html( (string) $running['source'] ) . '</code>'
				);
				?>
			</p>
			<progress max="100" value="<?php echo esc_attr( (string) $percent ); ?>"><?php echo esc_html( $percent . '%' ); ?></progress>
			<p class="wpb-geo-status" aria-live="polite">
				<?php
				printf(
					/* translators: 1: percent done, 2: ranges loaded so far. */
					esc_html__( 'Importing: %1$s%% done, %2$s ranges loaded…', 'wp-bouncer' ),
					esc_html( (string) $percent ),
					esc_html( number_format_i18n( (int) $running['imported'] ) )
				);
				?>
			</p>
			<div class="wpb-geo-actions">
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpb-geo-continue">
					<?php wp_nonce_field( 'wp_bouncer_geo_step' ); ?>
					<input type="hidden" name="action" value="wp_bouncer_geo_step">
					<?php submit_button( __( 'Continue import', 'wp-bouncer' ), 'primary', 'submit', false ); ?>
				</form>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( 'wp_bouncer_geo_cancel' ); ?>
					<input type="hidden" name="action" value="wp_bouncer_geo_cancel">
					<?php submit_button( __( 'Stop import', 'wp-bouncer' ), 'secondary', 'submit', false ); ?>
				</form>
			</div>
			<p class="description">
				<?php esc_html_e( 'The import runs in short steps so that no single request hits your host\'s time limit. Until it finishes, IPs whose ranges aren\'t loaded yet count as unknown, and country blocking lets them in.', 'wp-bouncer' ); ?>
			</p>
		</div>
	<?php endif; ?>
	<p>
		<?php if ( ! empty( $meta['rows'] ) ) : ?>
			<?php
			printf(
				/* translators: 1: number of ranges, 2: source, 3: date. */
				esc_html__( '%1$s IP ranges loaded from %2$s on %3$s.', 'wp-bouncer' ),
				'<strong>' . esc_html( number_format_i18n( (int) $meta['rows'] ) ) . '</strong>',
				'<code>' . esc_html( (string) $meta['source'] ) . '</code>',
				esc_html( wp_date( get_option( 'date_format' ), (int) $meta['imported'] ) )
			);
			?>
		<?php else : ?>
			<?php esc_html_e( 'No geo database loaded. Country blocking needs one, unless you read the country from a CDN header.', 'wp-bouncer' ); ?>
		<?php endif; ?>
	</p>
	<p class="description">
		<?php esc_html_e( 'Lookups are done locally against this table. No visitor data leaves your server. Supported formats: DB-IP "IP to Country Lite" (CSV, CC BY 4.0, updated monthly), IP2Location LITE DB1 (IPv4), or any start-IP,end-IP,country CSV. Gzipped files are fine. Importing replaces the current data. Re-import monthly to stay accurate.', 'wp-bouncer' ); ?>
	</p>

	<?php // The action is repeated in the URL so an over-size upload, which PHP empties, still reaches our handler. ?>
	<form method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin-post.php?action=wp_bouncer_geo_import' ) ); ?>"<?php echo null !== $running ? ' hidden' : ''; ?>>
		<?php wp_nonce_field( 'wp_bouncer_geo_import' ); ?>
		<input type="hidden" name="action" value="wp_bouncer_geo_import">
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="wpb-geo-url"><?php esc_html_e( 'Download from URL', 'wp-bouncer' ); ?></label></th>
				<td>
					<input id="wpb-geo-url" type="url" name="geo_url" class="large-text code" value="<?php echo esc_attr( $default_url ); ?>">
					<p class="description"><?php esc_html_e( 'Pre-filled with this month\'s free DB-IP country file. If you also choose a file below, the file is used instead.', 'wp-bouncer' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wpb-geo-file"><?php esc_html_e( 'Or upload a file', 'wp-bouncer' ); ?></label></th>
				<td>
					<input id="wpb-geo-file" type="file" name="geo_file" accept=".csv,.gz">
					<p class="description">
						<?php
						printf(
							/* translators: %s: size limit such as "8 MB". */
							esc_html__( 'This server accepts uploads up to %s. The DB-IP .csv.gz is about 5 MB; unpacked it is about 30 MB.', 'wp-bouncer' ),
							esc_html( size_format( wp_max_upload_size() ) )
						);
						?>
					</p>
				</td>
			</tr>
		</table>
		<?php submit_button( __( 'Import geo database', 'wp-bouncer' ), 'primary', 'submit', false ); ?>
		<p class="description"><?php esc_html_e( 'A full DB-IP country file is about 700,000 ranges. It imports in short steps with a progress bar and usually takes one to three minutes.', 'wp-bouncer' ); ?></p>
	</form>
</section>

<section class="wpb-card">
	<h2><?php esc_html_e( 'Unlock an IP', 'wp-bouncer' ); ?></h2>
	<p class="description"><?php esc_html_e( 'Lift a login lockout or rate-limit ban early. To unblock an IP on the blocklist, remove it on the Rules tab.', 'wp-bouncer' ); ?></p>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<?php wp_nonce_field( 'wp_bouncer_unlock_ip' ); ?>
		<input type="hidden" name="action" value="wp_bouncer_unlock_ip">
		<label class="screen-reader-text" for="wpb-unlock-ip"><?php esc_html_e( 'IP address', 'wp-bouncer' ); ?></label>
		<input id="wpb-unlock-ip" type="text" name="ip" class="regular-text code" placeholder="203.0.113.7" required>
		<?php submit_button( __( 'Unlock', 'wp-bouncer' ), 'secondary', 'submit', false ); ?>
	</form>
</section>

<section class="wpb-card">
	<h2><?php esc_html_e( 'Locked yourself out?', 'wp-bouncer' ); ?></h2>
	<p><?php esc_html_e( 'Add this line to wp-config.php to switch the firewall off, log in, fix the settings, then remove the line:', 'wp-bouncer' ); ?></p>
	<pre><code>define( 'WP_BOUNCER_DISABLE', true );</code></pre>
	<p><?php esc_html_e( 'Or rename the wp-content/plugins/wp-bouncer folder over FTP/SSH.', 'wp-bouncer' ); ?></p>
</section>
