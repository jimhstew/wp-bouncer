<?php
/**
 * WP_List_Table for the Traffic screen.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Admin;

use WPBouncer\Traffic\ClientClassifier;
use WPBouncer\Traffic\TrafficLog;

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( '\WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Paged, sortable, filterable table of requests.
 */
final class TrafficListTable extends \WP_List_Table {

	/**
	 * Log store.
	 *
	 * @var TrafficLog
	 */
	private TrafficLog $log;

	/**
	 * User id => login, filled per page.
	 *
	 * @var array<int, string>
	 */
	private array $users = array();

	/**
	 * Set up the TrafficListTable.
	 *
	 * @param TrafficLog $log Traffic store.
	 */
	public function __construct( TrafficLog $log ) {
		$this->log = $log;
		parent::__construct(
			array(
				'singular' => 'request',
				'plural'   => 'requests',
				'ajax'     => false,
			)
		);
	}

	/** {@inheritDoc} */
	public function get_columns() {
		return array(
			'created_at' => __( 'Time', 'wp-bouncer' ),
			'ip'         => __( 'IP', 'wp-bouncer' ),
			'client'     => __( 'Client', 'wp-bouncer' ),
			'request'    => __( 'Request', 'wp-bouncer' ),
			'status'     => __( 'Response', 'wp-bouncer' ),
			'referrer'   => __( 'Referrer', 'wp-bouncer' ),
			'user'       => __( 'User', 'wp-bouncer' ),
		);
	}

	/** {@inheritDoc} */
	protected function get_sortable_columns() {
		return array(
			'created_at' => array( 'created_at', true ),
			'ip'         => array( 'ip', false ),
			'client'     => array( 'client', false ),
			'status'     => array( 'status', false ),
		);
	}

	/**
	 * Load the rows for the current page.
	 *
	 * @return void
	 */
	public function prepare_items() {
		$per_page = 50;
		$filters  = AdminController::traffic_filters_from_request();
		// phpcs:disable WordPress.Security.NonceVerification -- read-only list parameters, sanitised here and never used to change state.
		$orderby = isset( $_GET['orderby'] ) ? sanitize_key( wp_unslash( $_GET['orderby'] ) ) : 'created_at';
		$order   = isset( $_GET['order'] ) ? sanitize_key( wp_unslash( $_GET['order'] ) ) : 'desc';
		// phpcs:enable WordPress.Security.NonceVerification

		$this->_column_headers = array( $this->get_columns(), array(), $this->get_sortable_columns(), 'created_at' );
		$this->items           = $this->log->query( $filters, $per_page, $this->get_pagenum(), $orderby, strtoupper( $order ) );
		$this->set_pagination_args(
			array(
				'total_items' => $this->log->count( $filters ),
				'per_page'    => $per_page,
			)
		);

		$ids = array_unique( array_filter( array_map( 'intval', wp_list_pluck( $this->items, 'user_id' ) ) ) );
		if ( $ids ) {
			foreach ( get_users(
				array(
					'include' => $ids,
					'fields'  => array( 'ID', 'user_login' ),
				)
			) as $user ) {
				$this->users[ (int) $user->ID ] = (string) $user->user_login;
			}
		}
	}

	/**
	 * Message shown when there are no rows.
	 *
	 * @return void
	 */
	public function no_items() {
		esc_html_e( 'No requests recorded yet.', 'wp-bouncer' );
	}

	/**
	 * Filter dropdowns and the export button.
	 *
	 * @param string $which top|bottom.
	 * @return void
	 */
	protected function extra_tablenav( $which ) {
		if ( 'top' !== $which ) {
			return;
		}
		$filters = AdminController::traffic_filters_from_request();
		echo '<div class="alignleft actions">';

		echo '<label class="screen-reader-text" for="wpb-filter-client">' . esc_html__( 'Filter by client', 'wp-bouncer' ) . '</label>';
		echo '<select name="client" id="wpb-filter-client"><option value="">' . esc_html__( 'All clients', 'wp-bouncer' ) . '</option>';
		foreach ( ClientClassifier::types() as $type ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $type ), selected( $filters['client'] ?? '', $type, false ), esc_html( AdminController::client_label( $type ) ) );
		}
		echo '</select>';

		echo '<label class="screen-reader-text" for="wpb-filter-status">' . esc_html__( 'Filter by response', 'wp-bouncer' ) . '</label>';
		echo '<select name="status" id="wpb-filter-status"><option value="">' . esc_html__( 'All responses', 'wp-bouncer' ) . '</option>';
		$classes = array(
			'2xx' => __( '2xx success', 'wp-bouncer' ),
			'3xx' => __( '3xx redirect', 'wp-bouncer' ),
			'4xx' => __( '4xx client error (includes blocks)', 'wp-bouncer' ),
			'5xx' => __( '5xx server error', 'wp-bouncer' ),
		);
		foreach ( $classes as $value => $label ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $value ), selected( $filters['status'] ?? '', $value, false ), esc_html( $label ) );
		}
		echo '</select>';

		submit_button( __( 'Filter', 'wp-bouncer' ), '', 'filter_action', false );
		echo '</div>';

		$args   = array_merge( AdminController::traffic_filters_to_args( $filters ), array( 'action' => 'wp_bouncer_export_traffic' ) );
		$export = wp_nonce_url( add_query_arg( $args, admin_url( 'admin-post.php' ) ), 'wp_bouncer_export_traffic' );
		echo '<div class="alignleft actions"><a class="button" href="' . esc_url( $export ) . '">' . esc_html__( 'Export CSV', 'wp-bouncer' ) . '</a></div>';
	}

	/**
	 * Fallback.
	 *
	 * @param array<string, string> $item        Row.
	 * @param string                $column_name Column.
	 * @return string
	 */
	protected function column_default( $item, $column_name ) {
		return esc_html( $item[ $column_name ] ?? '' );
	}

	/**
	 * Local time, UTC in a tooltip.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_created_at( $item ) {
		$local = get_date_from_gmt( $item['created_at'], get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );
		return sprintf( '<time datetime="%1$sZ" title="%1$s UTC">%2$s</time>', esc_attr( str_replace( ' ', 'T', $item['created_at'] ) ), esc_html( $local ) );
	}

	/**
	 * IP with row actions.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_ip( $item ) {
		$ip = $item['ip'];
		if ( '' === $ip ) {
			return '<span aria-hidden="true">—</span>';
		}
		$actions = array(
			'filter' => sprintf( '<a href="%s">%s</a>', esc_url( AdminController::url( 'traffic', array( 'ip' => $ip ) ) ), esc_html__( 'Only this IP', 'wp-bouncer' ) ),
			'blocks' => sprintf( '<a href="%s">%s</a>', esc_url( AdminController::url( 'log', array( 's' => $ip ) ) ), esc_html__( 'Its blocks', 'wp-bouncer' ) ),
			'block'  => sprintf(
				'<a href="%s">%s</a>',
				esc_url( AdminController::block_ip_url( $ip, 'traffic' ) ),
				esc_html__( 'Block IP', 'wp-bouncer' )
			),
		);
		return '<code>' . esc_html( $ip ) . '</code>' . $this->row_actions( $actions );
	}

	/**
	 * Client type, with the User-Agent in a tooltip and below.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_client( $item ) {
		return sprintf(
			'<span class="wpb-badge wpb-client-%1$s">%2$s</span><br><span class="wpb-trunc description" title="%3$s">%3$s</span>',
			esc_attr( $item['client'] ),
			esc_html( AdminController::client_label( $item['client'] ) ),
			esc_attr( $item['user_agent'] )
		);
	}

	/**
	 * Method and URL.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_request( $item ) {
		return sprintf( '<code class="wpb-trunc" title="%2$s">%1$s %2$s</code>', esc_html( $item['method'] ), esc_attr( $item['uri'] ) );
	}

	/**
	 * Response code badge.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_status( $item ) {
		$code = (int) $item['status'];
		if ( 0 === $code ) {
			return '<span aria-hidden="true">—</span>';
		}
		return sprintf( '<span class="wpb-badge wpb-status-%dxx" title="%s">%d</span>', (int) floor( $code / 100 ), esc_attr( get_status_header_desc( $code ) ), $code );
	}

	/**
	 * Referrer.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_referrer( $item ) {
		if ( '' === $item['referrer'] ) {
			return '<span aria-hidden="true">—</span>';
		}
		return sprintf( '<span class="wpb-trunc" title="%1$s">%1$s</span>', esc_attr( $item['referrer'] ) );
	}

	/**
	 * Logged-in user, if any.
	 *
	 * @param array<string, string> $item Row.
	 * @return string
	 */
	protected function column_user( $item ) {
		$id = (int) $item['user_id'];
		if ( 0 === $id ) {
			return '<span aria-hidden="true">—</span>';
		}
		$name = $this->users[ $id ] ?? '#' . $id;
		return sprintf( '<a href="%s">%s</a>', esc_url( get_edit_user_link( $id ) ), esc_html( $name ) );
	}
}
