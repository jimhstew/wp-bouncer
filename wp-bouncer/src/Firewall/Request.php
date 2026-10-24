<?php
/**
 * Snapshot of the incoming HTTP request, as seen by the rules.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Firewall;

defined( 'ABSPATH' ) || exit;

/**
 * Immutable view of the request.
 *
 * Rules read only from this object, never from superglobals, so they can be
 * unit tested by building a Request by hand. Anything that needs WordPress or
 * is expensive (login state, the raw body) is passed in as a closure and only
 * evaluated when a rule asks for it.
 */
final class Request {

	/**
	 * Client IP address.
	 *
	 * @var string
	 */
	private string $ip;
	/**
	 * HTTP method.
	 *
	 * @var string
	 */
	private string $method;
	/**
	 * Request URI.
	 *
	 * @var string
	 */
	private string $uri;
	/**
	 * Request path.
	 *
	 * @var string
	 */
	private string $path;
	/**
	 * Query parameters.
	 *
	 * @var array<string, mixed>
	 */
	private array $query;
	/**
	 * POST parameters.
	 *
	 * @var array<string, mixed>
	 */
	private array $post;
	/**
	 * The $_SERVER array.
	 *
	 * @var array<string, mixed>
	 */
	private array $server;

	/**
	 * Tells whether the current user is logged in.
	 *
	 * @var callable(): bool
	 */
	private $logged_in_resolver;
	/**
	 * Tells whether the current user is trusted.
	 *
	 * @var callable(): bool
	 */
	private $trusted_resolver;
	/**
	 * Reads the raw request body.
	 *
	 * @var callable(): string
	 */
	private $body_reader;

	/**
	 * Is this a request from the server itself?
	 *
	 * @var bool
	 */
	private bool $local;
	/**
	 * May bans and counters be kept for this client?
	 *
	 * @var bool
	 */
	private bool $bannable;

	/**
	 * Subject that bans and counters are keyed on instead of the IP.
	 *
	 * @var string
	 */
	private string $subject;

	/**
	 * Cached logged-in result.
	 *
	 * @var bool|null
	 */
	private ?bool $logged_in = null;
	/**
	 * Cached trusted result.
	 *
	 * @var bool|null
	 */
	private ?bool $trusted = null;
	/**
	 * Cached request body.
	 *
	 * @var string|null
	 */
	private ?string $body = null;

	/**
	 * Build a request.
	 *
	 * @param array<string, mixed> $args {
	 *     Request fields.
	 *
	 *     @type string   $ip          Client IP (already resolved by IpResolver).
	 *     @type string   $method      HTTP method.
	 *     @type string   $uri         Raw REQUEST_URI.
	 *     @type array    $query       Unslashed $_GET.
	 *     @type array    $post        Unslashed $_POST.
	 *     @type array    $server      $_SERVER (used for headers).
	 *     @type callable $logged_in   Returns whether a user is logged in.
	 *     @type callable $trusted     Returns whether the user is a site administrator.
	 *     @type callable $body        Returns the raw request body.
	 *     @type bool     $local       Request from the server itself (loopback, no forwarding header). Default false.
	 *     @type bool     $bannable    Bans, lockouts and counters may be kept for this client. Default true.
	 *     @type string   $subject     Key for bans and counters when it must differ from the IP. Default ''.
	 * }
	 */
	public function __construct( array $args ) {
		$this->ip     = (string) ( $args['ip'] ?? '' );
		$this->method = strtoupper( (string) ( $args['method'] ?? 'GET' ) );
		$this->uri    = (string) ( $args['uri'] ?? '/' );
		$this->query  = is_array( $args['query'] ?? null ) ? $args['query'] : array();
		$this->post   = is_array( $args['post'] ?? null ) ? $args['post'] : array();
		$this->server = is_array( $args['server'] ?? null ) ? $args['server'] : array();
		$this->path   = self::normalize_path( $this->uri );

		$this->local    = ! empty( $args['local'] );
		$this->subject  = (string) ( $args['subject'] ?? '' );
		$this->bannable = ! array_key_exists( 'bannable', $args ) || ! empty( $args['bannable'] );

		$this->logged_in_resolver = $args['logged_in'] ?? static function (): bool {
			return false;
		};
		$this->trusted_resolver   = $args['trusted'] ?? static function (): bool {
			return false;
		};
		$this->body_reader        = $args['body'] ?? static function (): string {
			return '';
		};
	}

	/**
	 * Build from PHP superglobals. Values must already be unslashed.
	 *
	 * @param string               $ip        Resolved client IP.
	 * @param array<string, mixed> $server    $_SERVER.
	 * @param array<string, mixed> $get       $_GET.
	 * @param array<string, mixed> $post      $_POST.
	 * @param callable             $logged_in Login-state resolver.
	 * @param callable             $trusted   Admin-state resolver.
	 * @param bool                 $local     Request from the server itself.
	 * @param bool                 $bannable  Bans and counters may be kept for this client.
	 * @param string               $subject   Key for bans and counters when it must differ from the IP.
	 */
	public static function from_globals( string $ip, array $server, array $get, array $post, callable $logged_in, callable $trusted, bool $local = false, bool $bannable = true, string $subject = '' ): self {
		return new self(
			array(
				'ip'        => $ip,
				'method'    => (string) ( $server['REQUEST_METHOD'] ?? 'GET' ),
				'uri'       => (string) ( $server['REQUEST_URI'] ?? '/' ),
				'query'     => $get,
				'post'      => $post,
				'server'    => $server,
				'logged_in' => $logged_in,
				'trusted'   => $trusted,
				'local'     => $local,
				'bannable'  => $bannable,
				'subject'   => $subject,
				'body'      => static function (): string {
					// php://input can be read more than once on PHP >= 5.6, so WordPress still sees it later.
					$body = file_get_contents( 'php://input', false, null, 0, 1048576 );
					return false === $body ? '' : $body;
				},
			)
		);
	}

	/**
	 * Lowercase, URL-decoded path with duplicate slashes collapsed.
	 *
	 * Normalising defeats trivial evasions such as /XMLRPC.php or //wp-login.php.
	 *
	 * @param string $uri Raw request URI.
	 */
	public static function normalize_path( string $uri ): string {
		$path = (string) parse_url( 'http://x' . ( '/' === substr( $uri, 0, 1 ) ? '' : '/' ) . $uri, PHP_URL_PATH ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- pure-PHP class unit-tested without WordPress; only the path component of a fixed-scheme URL is read, so PHP-version differences do not matter.
		$path = rawurldecode( $path );
		$path = str_replace( '\\', '/', $path );
		$path = (string) preg_replace( '#/+#', '/', $path );
		return strtolower( '' === $path ? '/' : $path );
	}

	/** Client IP address. */
	public function ip(): string {
		return $this->ip;
	}

	/**
	 * Did the request come from the server itself (WP-Cron, health checks)?
	 *
	 * Set by the caller from IpResolver::is_local_request(); local requests skip every rule.
	 */
	public function is_local(): bool {
		return $this->local;
	}

	/**
	 * May this client be banned, locked out or counted?
	 *
	 * False for loopback and trusted-proxy addresses, and while the client IP
	 * can't be told apart from a shared proxy. Rules must still refuse the
	 * current request when it matches, but must not keep state against the IP.
	 */
	public function can_be_banned(): bool {
		return $this->bannable;
	}

	/**
	 * What bans, lockouts and counters are keyed on: the IP, or a distinct
	 * subject such as "rejected:<proxy>" (see IpResolver::rejected_subject()).
	 */
	public function key_ip(): string {
		return '' !== $this->subject ? $this->subject : $this->ip;
	}

	/** Upper-case HTTP method. */
	public function method(): string {
		return $this->method;
	}

	/** Raw request URI including query string. */
	public function uri(): string {
		return $this->uri;
	}

	/** Normalised path (see normalize_path()). */
	public function path(): string {
		return $this->path;
	}

	/**
	 * Get the query parameters.
	 *
	 * @return array<string, mixed> Query parameters.
	 */
	public function query(): array {
		return $this->query;
	}

	/**
	 * Get the POST parameters.
	 *
	 * @return array<string, mixed> POST parameters.
	 */
	public function post(): array {
		return $this->post;
	}

	/** User-Agent header ('' when absent). */
	public function user_agent(): string {
		return (string) ( $this->server['HTTP_USER_AGENT'] ?? '' );
	}

	/**
	 * Read a request header or a server variable.
	 *
	 * Looks up HTTP_<NAME> first, then the raw name, so both "CF-IPCountry"
	 * and server variables such as "GEOIP_COUNTRY_CODE" work.
	 *
	 * @param string $name Header name, e.g. "X-Forwarded-For".
	 */
	public function header( string $name ): string {
		// A name without a hyphen may be a server variable (GEOIP_COUNTRY_CODE) that a client could
		// forge as a header (Geoip-Country-Code), so the real variable wins.
		if ( false === strpos( $name, '-' ) && isset( $this->server[ $name ] ) ) {
			return (string) $this->server[ $name ];
		}
		$key = 'HTTP_' . strtoupper( str_replace( '-', '_', $name ) );
		if ( isset( $this->server[ $key ] ) ) {
			return (string) $this->server[ $key ];
		}
		return (string) ( $this->server[ $name ] ?? '' );
	}

	/** Raw request body (read lazily, capped at 1 MB). */
	public function body(): string {
		if ( null === $this->body ) {
			$this->body = (string) call_user_func( $this->body_reader );
		}
		return $this->body;
	}

	/** Is any user logged in? */
	public function is_logged_in(): bool {
		if ( null === $this->logged_in ) {
			$this->logged_in = (bool) call_user_func( $this->logged_in_resolver );
		}
		return $this->logged_in;
	}

	/**
	 * Is the user a trusted administrator?
	 *
	 * Trusted users skip the content-inspection rules (WAF, rate limit, user
	 * enumeration) because they legitimately post HTML and scripts.
	 */
	public function is_trusted(): bool {
		if ( null === $this->trusted ) {
			$this->trusted = (bool) call_user_func( $this->trusted_resolver );
		}
		return $this->trusted;
	}

	/** Is this a request to wp-login.php (including /wp-login.php/extra PATH_INFO)? */
	public function is_login(): bool {
		return self::has_segment( $this->path, '/wp-login.php' );
	}

	/** Is this a request to xmlrpc.php (including /xmlrpc.php/extra PATH_INFO)? */
	public function is_xmlrpc(): bool {
		return self::has_segment( $this->path, '/xmlrpc.php' );
	}

	/**
	 * Is this a request inside /wp-admin/ (including admin-ajax.php)?
	 *
	 * The admin folder must be at the start of the path (after the site's own
	 * folder, if WordPress is installed in one), so "/index.php/wp-admin/" does
	 * not count. When the server reports SCRIPT_NAME it must point into
	 * wp-admin too, which is how a subdirectory install is told apart.
	 */
	public function is_admin_area(): bool {
		$base   = '';
		$script = strtolower( (string) ( $this->server['SCRIPT_NAME'] ?? '' ) );
		if ( '' !== $script ) {
			$pos = strpos( $script, '/wp-admin/' );
			if ( false === $pos ) {
				return false;
			}
			$base = substr( $script, 0, $pos );
		}
		return 0 === strpos( $this->path, $base . '/wp-admin/' ) || $this->path === $base . '/wp-admin';
	}

	/**
	 * The REST route being requested, if any ('' otherwise).
	 *
	 * Handles both pretty permalinks (/wp-json/wp/v2/users) and the
	 * ?rest_route=/wp/v2/users fallback.
	 */
	public function rest_route(): string {
		// WordPress reads query variables from the query string and from a POST body.
		foreach ( array( $this->query, $this->post ) as $source ) {
			if ( isset( $source['rest_route'] ) && is_string( $source['rest_route'] ) ) {
				return strtolower( '/' . ltrim( $source['rest_route'], '/' ) );
			}
		}
		$pos = strpos( $this->path, '/wp-json/' );
		if ( false !== $pos ) {
			return substr( $this->path, $pos + strlen( '/wp-json' ) );
		}
		return '';
	}

	/**
	 * Does the path contain the file name as a whole segment, at the end or followed by "/"?
	 *
	 * @param string $path Normalised path.
	 * @param string $name File name with leading slash.
	 */
	private static function has_segment( string $path, string $name ): bool {
		$pos = strpos( $path, $name );
		while ( false !== $pos ) {
			$end = $pos + strlen( $name );
			if ( strlen( $path ) === $end || '/' === $path[ $end ] ) {
				return true;
			}
			$pos = strpos( $path, $name, $end );
		}
		return false;
	}
}
