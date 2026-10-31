<?php
/**
 * Threats by country panel (Activity Log tab). Everything is rendered by PHP and escaped on output.
 *
 * @package WPBouncer
 * @var array<string, string>                          $log_filters Activity Log filters.
 * @var \WPBouncer\Log\DateRange                       $range       Date range.
 * @var \WPBouncer\ThreatMap\ThreatQuery               $query       Query.
 * @var string                                         $state       filtered_out|busy|error|no_geo|empty|ok.
 * @var array<string, mixed>|null                      $model       MapModel::build() output when state is ok.
 * @var \WPBouncer\ThreatMap\CountryTally|null         $tally       Tally.
 * @var int                                            $built       Build time of the numbers.
 * @var int                                            $now         Current time.
 * @var bool                                           $geo         Is a geolocation database loaded?
 * @var bool                                           $show_base   Is the base map file readable?
 * @var string                                         $base_url    URL of the base map.
 * @var int                                            $width       Map width in viewBox units.
 * @var int                                            $height      Map height in viewBox units.
 * @var \WPBouncer\Rules\CountryRule                    $country_rule The country rule, for the "Blocked" badges.
 * @var bool                                           $monitor     Is the firewall in monitor mode?
 */

use WPBouncer\Admin\AdminController;
use WPBouncer\Geo\Countries;
use WPBouncer\ThreatMap\HeatScale;

defined( 'ABSPATH' ) || exit;

$wpb_date_format = (string) get_option( 'date_format' );
$wpb_window      = sprintf(
	/* translators: 1: first day, 2: last day. */
	__( '%1$s – %2$s', 'wp-bouncer' ),
	wp_date( $wpb_date_format, $range->start_ts ),
	wp_date( $wpb_date_format, $range->end_ts )
);
if ( ! $range->explicit ) {
	/* translators: %s: a date range such as "27 Sep 2026 – 26 Oct 2026". */
	$wpb_window = sprintf( __( 'Last 30 days (%s)', 'wp-bouncer' ), $wpb_window );
}
$wpb_country = $query->country();
$wpb_clear   = AdminController::url( 'log', AdminController::log_filters_to_args( array_diff_key( $log_filters, array( 'country' => 1 ) ) ) );
?>
<section class="wpb-map" aria-labelledby="wpb-map-h">
	<div class="wpb-map-head">
		<h2 id="wpb-map-h"><?php esc_html_e( 'Threats by country', 'wp-bouncer' ); ?></h2>
		<button type="button" class="button-link wpb-map-toggle" aria-expanded="true" aria-controls="wpb-map-body" hidden><?php esc_html_e( 'Hide map', 'wp-bouncer' ); ?></button>
	</div>
	<div id="wpb-map-body" class="wpb-map-body">
		<p class="wpb-map-window">
			<?php
			echo esc_html( $wpb_window ) . '. ';
			esc_html_e( 'Ignores the search box and the IP filter.', 'wp-bouncer' );
			if ( '' !== $wpb_country ) {
				echo ' ';
				/* translators: %s: country name and code. */
				echo esc_html( sprintf( __( 'Country: %s', 'wp-bouncer' ), sprintf( '%1$s (%2$s)', Countries::name( $wpb_country ), $wpb_country ) ) ) . ' · ';
				echo '<a href="' . esc_url( $wpb_clear ) . '">' . esc_html__( 'Clear', 'wp-bouncer' ) . '</a>';
			}
			?>
		</p>
		<?php if ( 'filtered_out' === $state ) : ?>
			<p>
				<?php
				if ( 'action' === $query->reason() ) {
					/* translators: %s: the action chosen in the filter. */
					echo esc_html( sprintf( __( 'The map counts blocked requests and lockouts only, so nothing matches the action filter ‘%s’.', 'wp-bouncer' ), AdminController::action_label( (string) ( $log_filters['action'] ?? '' ) ) ) );
				} else {
					esc_html_e( 'No threats match this filter.', 'wp-bouncer' );
				}
				?>
			</p>
		<?php elseif ( 'busy' === $state ) : ?>
			<p><?php esc_html_e( 'The map is being updated. Reload the page in a few seconds.', 'wp-bouncer' ); ?></p>
		<?php elseif ( 'error' === $state ) : ?>
			<p><?php esc_html_e( 'The map could not be loaded. The log table below still works.', 'wp-bouncer' ); ?></p>
		<?php elseif ( 'empty' === $state ) : ?>
			<p><?php esc_html_e( 'No threats recorded in this period yet.', 'wp-bouncer' ); ?></p>
		<?php elseif ( 'no_geo' === $state ) : ?>
			<p>
				<?php esc_html_e( 'Country data needs the geolocation database.', 'wp-bouncer' ); ?>
				<a href="<?php echo esc_url( AdminController::url( 'tools' ) ); ?>"><?php esc_html_e( 'Set it up on the Tools tab', 'wp-bouncer' ); ?></a>
			</p>
			<?php if ( null !== $tally ) : ?>
				<p class="wpb-map-unknown">
					<?php
					/* translators: %s: number of threats. */
					echo esc_html( sprintf( _n( 'Unknown location: %s threat', 'Unknown location: %s threats', $tally->unknown(), 'wp-bouncer' ), number_format_i18n( $tally->unknown() ) ) );
					?>
				</p>
			<?php endif; ?>
		<?php elseif ( null !== $model && null !== $tally ) : ?>
			<?php
			$wpb_rows = $tally->countries();
			$wpb_open = 10;
			?>
			<div class="wpb-map-grid">
				<figure class="wpb-map-figure">
					<div class="wpb-map-canvas" style="--wpb-map-w: <?php echo (int) $width; ?>; --wpb-map-h: <?php echo (int) $height; ?>;">
						<?php if ( $show_base ) : ?>
							<img class="wpb-map-base" src="<?php echo esc_url( $base_url . '?ver=' . rawurlencode( \WPBouncer\Plugin::VERSION ) ); ?>" alt="" width="<?php echo (int) $width; ?>" height="<?php echo (int) $height; ?>" decoding="async">
						<?php endif; ?>
						<svg class="wpb-map-dots" viewBox="0 0 <?php echo (int) $width; ?> <?php echo (int) $height; ?>" role="group" aria-labelledby="wpb-map-h" aria-describedby="wpb-map-desc">
							<?php foreach ( $model['dots'] as $wpb_i => $wpb_dot ) : ?>
								<?php
								$wpb_name  = Countries::name( $wpb_dot['code'] );
								$wpb_title = sprintf( '%1$s (%2$s)', $wpb_name, $wpb_dot['code'] );
								$wpb_n     = number_format_i18n( $wpb_dot['count'] );
								/* translators: %s: number of threats. */
								$wpb_count = sprintf( _n( '%s threat', '%s threats', $wpb_dot['count'], 'wp-bouncer' ), $wpb_n );
								?>
								<circle class="wpb-heat-<?php echo (int) $wpb_dot['bucket']; ?>" cx="<?php echo esc_attr( (string) round( $wpb_dot['x'], 1 ) ); ?>" cy="<?php echo esc_attr( (string) round( $wpb_dot['y'], 1 ) ); ?>" r="<?php echo esc_attr( (string) round( $wpb_dot['r'], 2 ) ); ?>" tabindex="<?php echo 0 === $wpb_i ? '0' : '-1'; ?>" role="img" aria-label="<?php echo esc_attr( $wpb_title . ': ' . $wpb_count ); ?>" data-cc="<?php echo esc_attr( $wpb_dot['code'] ); ?>" data-title="<?php echo esc_attr( $wpb_title ); ?>" data-count="<?php echo esc_attr( $wpb_count ); ?>"></circle>
							<?php endforeach; ?>
						</svg>
						<div class="wpb-map-tip" role="tooltip" hidden></div>
					</div>
					<figcaption id="wpb-map-desc"><?php esc_html_e( 'Each dot is a country that threats came from. Brighter red and larger dots mean more threats. The table lists the same numbers.', 'wp-bouncer' ); ?></figcaption>
					<div class="wpb-map-legend">
						<span><?php esc_html_e( 'Logarithmic scale:', 'wp-bouncer' ); ?></span>
						<span><?php echo esc_html( number_format_i18n( (int) $model['min'] ) ); ?></span>
						<span class="wpb-map-swatches" aria-hidden="true">
							<?php if ( $model['min'] === $model['max'] ) : ?>
								<i class="wpb-heat-7"></i>
							<?php else : ?>
								<?php for ( $wpb_b = 0; $wpb_b < HeatScale::STEPS; $wpb_b++ ) : ?>
									<i class="wpb-heat-<?php echo (int) $wpb_b; ?>"></i>
								<?php endfor; ?>
							<?php endif; ?>
						</span>
						<?php if ( $model['min'] !== $model['max'] ) : ?>
							<span><?php echo esc_html( number_format_i18n( (int) $model['max'] ) ); ?></span>
						<?php endif; ?>
					</div>
					<p class="wpb-map-unknown">
						<?php
						/* translators: %s: number of threats. */
						echo esc_html( sprintf( _n( 'Unknown location: %s threat', 'Unknown location: %s threats', (int) $model['unknown'], 'wp-bouncer' ), number_format_i18n( (int) $model['unknown'] ) ) );
						?>
					</p>
					<?php if ( ! $geo ) : ?>
						<p class="description"><?php esc_html_e( 'No geolocation database is installed, so new entries only get a country if your proxy sends a country header.', 'wp-bouncer' ); ?></p>
					<?php endif; ?>
				</figure>
				<div class="wpb-map-top">
					<table class="widefat striped">
						<caption><?php esc_html_e( 'Top countries', 'wp-bouncer' ); ?></caption>
						<thead><tr>
							<th scope="col"><?php esc_html_e( 'Country', 'wp-bouncer' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Code', 'wp-bouncer' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Threats', 'wp-bouncer' ); ?></th>
						</tr></thead>
						<tbody>
							<?php $wpb_pos = 0; ?>
							<?php foreach ( $wpb_rows as $wpb_code => $wpb_cnt ) : ?>
								<?php
								$wpb_code = (string) $wpb_code;
								$wpb_url  = AdminController::url( 'log', AdminController::log_filters_to_args( $log_filters ) + array( 'country' => $wpb_code ) );
								$wpb_off  = isset( $model['unplaced'][ $wpb_code ] );
								++$wpb_pos;
								?>
								<tr<?php echo $wpb_pos > $wpb_open ? ' class="wpb-map-extra"' : ''; ?>>
									<td>
										<span aria-hidden="true"><?php echo esc_html( AdminController::flag( $wpb_code ) ); ?></span>
										<a href="<?php echo esc_url( $wpb_url ); ?>"><?php echo esc_html( Countries::name( $wpb_code ) ); ?></a>
										<?php echo AdminController::country_block_badge( $country_rule, $monitor, $wpb_code ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in country_block_badge(). ?>
										<?php if ( $wpb_off ) : ?>
											<span class="wpb-map-off"><?php esc_html_e( '(not on the map)', 'wp-bouncer' ); ?></span>
										<?php endif; ?>
									</td>
									<td><?php echo esc_html( $wpb_code ); ?></td>
									<td><?php echo esc_html( number_format_i18n( $wpb_cnt ) ); ?></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					<?php if ( count( $wpb_rows ) > $wpb_open ) : ?>
						<?php
						/* translators: %s: number of countries. */
						$wpb_more = sprintf( _n( 'Show all %s country', 'Show all %s countries', count( $wpb_rows ), 'wp-bouncer' ), number_format_i18n( count( $wpb_rows ) ) );
						?>
						<button type="button" class="button wpb-map-more" aria-expanded="false" data-more="<?php echo esc_attr( $wpb_more ); ?>" hidden><?php echo esc_html( $wpb_more ); ?></button>
					<?php endif; ?>
				</div>
			</div>
			<?php if ( $built > 0 && $now - $built >= 600 ) : ?>
				<p class="description">
					<?php
					/* translators: %s: how long ago, for example "5 minutes". */
					echo esc_html( sprintf( __( 'Updated %s ago.', 'wp-bouncer' ), human_time_diff( $built, $now ) ) );
					?>
				</p>
			<?php endif; ?>
		<?php endif; ?>
		<p class="description"><?php esc_html_e( 'Counts blocked requests and lockouts. Monitor-only matches, alerts and admin logins are not counted.', 'wp-bouncer' ); ?></p>
		<p class="description"><?php esc_html_e( 'Country comes from the visitor\'s IP address (geolocation database or a trusted proxy header). It can be wrong, and behind an untrusted proxy it can be forged. Use the map as a hint before blocking a country, not as proof.', 'wp-bouncer' ); ?></p>
	</div>
</section>
