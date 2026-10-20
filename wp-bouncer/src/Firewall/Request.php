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

	private string $ip;
	private string $method;
	private string $uri;
	private string $path;
	/** @var array<string, mixed> */
	private array $query;
	/** @var array<string, mixed> */
	private array $post;
	/** @var array<string, mixed> */
	private array $server;

	/** @var callable(): bool */
	private $logged_in_resolver;
	/** @var callable(): bool */
	private $trusted_resolver;
	/** @var callable(): string */
	private $body_reader;

	private ?bool $logged_in = null;
	private ?bool $trusted   = null;
	private ?string $body    = null;

	/**
	 * Build a request.
	 *
	 * @param array<string, mixed> $args {
	 *     @type string   $ip          Client IP (already resolved by IpResolver).
	 *     @type string   $method      HTTP method.
	 *     @type string   $uri         Raw REQUEST_URI.
	 *     @type array    $query       Unslashed $_GET.
	 *     @type array    $post        Unslashed $_POST.
	 *     @type array    $server      $_SERVER (used for headers).
	 *     @type callable $logged_in   Returns whether a user is logged in.
	 *     @type callable $trusted     Returns whether the user is a site administrator.
	 *     @type callable $body        Returns the raw request body.
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
	 */
	public static function from_globals( string $ip, array $server, array $get, array $post, callable $logged_in, callable $trusted ): self {
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
		$path = (string) parse_url( 'http://x' . ( '/' === substr( $uri, 0, 1 ) ? '' : '/' ) . $uri, PHP_URL_PATH );
		$path = rawurldecode( $path );
		$path = str_replace( '\\', '/', $path );
		$path = (string) preg_replace( '#/+#', '/', $path );
		return strtolower( '' === $path ? '/' : $path );
	}

	/** Client IP address. */
	public function ip(): string {
		return $this->ip;
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

	/** @return array<string, mixed> Query parameters. */
	public function query(): array {
		return $this->query;
	}

	/** @return array<string, mixed> POST parameters. */
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

	/** Is this a request to wp-login.php? */
	public function is_login(): bool {
		return self::ends_with( $this->path, '/wp-login.php' );
	}

	/** Is this a request to xmlrpc.php? */
	public function is_xmlrpc(): bool {
		return self::ends_with( $this->path, '/xmlrpc.php' );
	}

	/** Is this a request inside /wp-admin/ (including admin-ajax.php)? */
	public function is_admin_area(): bool {
		return false !== strpos( $this->path, '/wp-admin/' ) || self::ends_with( $this->path, '/wp-admin' );
	}

	/**
	 * The REST route being requested, if any ('' otherwise).
	 *
	 * Handles both pretty permalinks (/wp-json/wp/v2/users) and the
	 * ?rest_route=/wp/v2/users fallback.
	 */
	public function rest_route(): string {
		if ( isset( $this->query['rest_route'] ) && is_string( $this->query['rest_route'] ) ) {
			return strtolower( '/' . ltrim( $this->query['rest_route'], '/' ) );
		}
		$pos = strpos( $this->path, '/wp-json/' );
		if ( false !== $pos ) {
			return substr( $this->path, $pos + strlen( '/wp-json' ) );
		}
		return '';
	}

	/**
	 * Does $haystack end with $needle?
	 *
	 * @param string $haystack Subject.
	 * @param string $needle   Suffix.
	 */
	private static function ends_with( string $haystack, string $needle ): bool {
		return substr( $haystack, -strlen( $needle ) ) === $needle;
	}
}
