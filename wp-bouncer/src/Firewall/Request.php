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

	/** Default cap, in bytes, for body(). WafRule reads JSON bodies through body_limited() with its own cap. */
	public const BODY_CAP = 1048576;

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
	 * Returns whether the user can edit posts, or null.
	 *
	 * @var callable|null
	 */
	private $editor_resolver;

	/**
	 * Returns whether valid application-password credentials of an editor came with the request.
	 *
	 * @var callable|null
	 */
	private $basic_editor_resolver;

	/**
	 * Verifies a REST nonce, or null.
	 *
	 * @var callable|null
	 */
	private $nonce_checker;

	/**
	 * Cached can_edit_posts() answer.
	 *
	 * @var bool|null
	 */
	private ?bool $editor = null;
	/**
	 * Reads the raw request body.
	 *
	 * @var callable(int): string
	 */
	private $body_reader;

	/**
	 * Opens the raw request body as a stream, or null to wrap body().
	 *
	 * @var (callable(): mixed)|null
	 */
	private $stream_opener;

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
	 * Body read by body_limited().
	 *
	 * @var string|null
	 */
	private ?string $limited = null;

	/**
	 * Cap used for $limited.
	 *
	 * @var int
	 */
	private int $limited_cap = 0;

	/**
	 * Origins (or bare host names) that count as this site, or a closure returning them (evaluated when needed, so filters added later apply).
	 *
	 * @var string[]|\Closure
	 */
	private $own_hosts = array();

	/**
	 * Cached FetchContext result.
	 *
	 * @var string|null
	 */
	private ?string $fetch_context = null;

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
	 *     @type callable $editor      Returns whether the user can edit posts.
	 *     @type callable $body        Returns the raw request body.
	 *     @type string[]|\Closure $own_hosts Origins (or bare host names) that count as this site, or a closure returning them. Default none.
	 *     @type callable $body_stream Opens the raw request body as a readable stream (no size cap).
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

		$own             = $args['own_hosts'] ?? array();
		$this->own_hosts = $own instanceof \Closure || is_array( $own ) ? $own : array();
		$this->local     = ! empty( $args['local'] );
		$this->subject   = (string) ( $args['subject'] ?? '' );
		$this->bannable  = ! array_key_exists( 'bannable', $args ) || ! empty( $args['bannable'] );

		$this->logged_in_resolver    = $args['logged_in'] ?? static function (): bool {
			return false;
		};
		$this->basic_editor_resolver = isset( $args['basic_editor'] ) && is_callable( $args['basic_editor'] ) ? $args['basic_editor'] : null;
		$this->nonce_checker         = isset( $args['nonce_check'] ) && is_callable( $args['nonce_check'] ) ? $args['nonce_check'] : null;
		$this->editor_resolver       = isset( $args['editor'] ) && is_callable( $args['editor'] ) ? $args['editor'] : null;
		$this->trusted_resolver      = $args['trusted'] ?? static function (): bool {
			return false;
		};
		$this->body_reader           = $args['body'] ?? static function ( int $limit = 0 ): string { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- same signature as the real reader.
			return '';
		};
		$this->stream_opener         = isset( $args['body_stream'] ) && is_callable( $args['body_stream'] ) ? $args['body_stream'] : null;
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
	 * @param string[]|\Closure    $own_hosts Origins (or bare host names) that count as this site, or a closure returning them.
	 * @param callable|null        $editor    Returns whether the user can edit posts (null: no).
	 * @param callable|null        $basic_editor Returns whether valid application-password credentials of an editor came with the request.
	 * @param callable|null        $nonce_check  Verifies a REST nonce: fn( string ): bool (null: presence is enough).
	 */
	public static function from_globals( string $ip, array $server, array $get, array $post, callable $logged_in, callable $trusted, bool $local = false, bool $bannable = true, string $subject = '', \Closure|array $own_hosts = array(), ?callable $editor = null, ?callable $basic_editor = null, ?callable $nonce_check = null ): self {
		return new self(
			array(
				'ip'           => $ip,
				'method'       => (string) ( $server['REQUEST_METHOD'] ?? 'GET' ),
				'uri'          => (string) ( $server['REQUEST_URI'] ?? '/' ),
				'query'        => $get,
				'post'         => $post,
				'server'       => $server,
				'logged_in'    => $logged_in,
				'trusted'      => $trusted,
				'editor'       => $editor,
				'basic_editor' => $basic_editor,
				'nonce_check'  => $nonce_check,
				'local'        => $local,
				'bannable'     => $bannable,
				'subject'      => $subject,
				'own_hosts'    => $own_hosts,
				'body_stream'  => static function () {
					// Not capped: lets a rule read a large body in chunks without holding it in memory.
					return fopen( 'php://input', 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- php://input is not a file the Filesystem API can open.
				},
				'body'         => static function ( int $limit = self::BODY_CAP ): string {
					// php://input can be read more than once on PHP >= 5.6, so WordPress still sees it later.
					$body = file_get_contents( 'php://input', false, null, 0, $limit );
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

	/**
	 * Is the body declared as JSON, the way WordPress decides it (wp_is_json_media_type())?
	 *
	 * Covers application/json, any application/*+json, +oembed, and lists such as
	 * "text/plain, application/json". Doesn't read the body.
	 */
	public function is_json(): bool {
		$type = (string) ( $this->server['CONTENT_TYPE'] ?? $this->server['HTTP_CONTENT_TYPE'] ?? '' );
		return 1 === preg_match( '/(^|\s|,)application\/([\w!#\$&-\^\.\+]+\+)?json(\+oembed)?($|\s|;|,)/i', $type );
	}

	/**
	 * Could an undeclared body still be JSON? False for multipart form data
	 * (php://input is empty there), an empty body (CONTENT_LENGTH 0), and a GET or HEAD
	 * without Transfer-Encoding. Urlencoded bodies are sniffed too, because a
	 * plugin may json_decode the raw body whatever the type says. Doesn't read the body.
	 */
	public function could_be_json(): bool {
		$length = (string) ( $this->server['CONTENT_LENGTH'] ?? $this->server['HTTP_CONTENT_LENGTH'] ?? '' );
		if ( '0' === $length ) {
			return false;
		}
		if ( in_array( $this->method, array( 'GET', 'HEAD' ), true ) && empty( $this->server['HTTP_TRANSFER_ENCODING'] ) ) {
			return false;
		}
		$type = strtolower( ltrim( (string) ( $this->server['CONTENT_TYPE'] ?? $this->server['HTTP_CONTENT_TYPE'] ?? '' ) ) );
		return 0 !== strpos( $type, 'multipart/form-data' );
	}

	/**
	 * At most $cap + 1 bytes of the raw body (one extra byte tells the caller it was cut off).
	 *
	 * @param int $cap Largest body the caller accepts.
	 */
	public function body_limited( int $cap ): string {
		$cap = max( 0, $cap );
		if ( null !== $this->limited && ( $this->limited_cap >= $cap || strlen( $this->limited ) <= $this->limited_cap ) ) {
			return substr( $this->limited, 0, $cap + 1 );
		}
		$this->limited     = substr( (string) call_user_func( $this->body_reader, $cap + 1 ), 0, $cap + 1 );
		$this->limited_cap = $cap;
		return $this->limited;
	}

	/** Raw request body (read lazily, capped at 1 MB). */
	public function body(): string {
		if ( null === $this->body ) {
			$this->body = (string) call_user_func( $this->body_reader, self::BODY_CAP );
		}
		return $this->body;
	}

	/**
	 * The raw request body as a new readable stream, positioned at the start.
	 *
	 * Unlike body(), this has no size cap. The caller must fclose() it.
	 *
	 * @return resource|null
	 */
	public function body_stream() {
		if ( null !== $this->stream_opener ) {
			$stream = call_user_func( $this->stream_opener );
			return is_resource( $stream ) ? $stream : null;
		}
		$stream = fopen( 'php://memory', 'w+b' ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- in-memory stream, not a file.
		if ( false === $stream ) {
			return null;
		}
		fwrite( $stream, $this->body() ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- in-memory stream.
		rewind( $stream );
		return $stream;
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

	/**
	 * Can the user edit posts (editor, author, contributor and up)?
	 *
	 * Their saves go through JSON REST calls with HTML and code, so the WAF's
	 * JSON scan skips them. Two ways in. Valid application-password credentials of
	 * such a user (checked by the basic_editor resolver; Basic auth isn't sent
	 * automatically across sites, so no nonce is needed). Or a logged-in user with
	 * a nonce (X-WP-Nonce header or _wpnonce parameter), so a cross-site request
	 * riding on a cookie is scanned like anyone else's; on REST paths the nonce
	 * must verify as a "wp_rest" nonce. False when no resolver was given.
	 */
	public function can_edit_posts(): bool {
		if ( null === $this->editor ) {
			$this->editor = $this->basic_editor() || ( $this->has_valid_nonce() && null !== $this->editor_resolver && (bool) call_user_func( $this->editor_resolver ) );
		}
		return $this->editor;
	}

	/** Did the request bring valid application-password credentials of an editor? */
	private function basic_editor(): bool {
		return null !== $this->basic_editor_resolver && (bool) call_user_func( $this->basic_editor_resolver );
	}

	/** Does the request carry a nonce (verified as a REST nonce on REST paths)? */
	private function has_valid_nonce(): bool {
		$nonce = $this->header( 'X-WP-Nonce' );
		foreach ( array( $this->query, $this->post ) as $source ) {
			if ( '' === $nonce && isset( $source['_wpnonce'] ) && is_string( $source['_wpnonce'] ) ) {
				$nonce = $source['_wpnonce'];
			}
		}
		if ( '' === $nonce ) {
			return false;
		}
		if ( '' !== $this->rest_route() && null !== $this->nonce_checker ) {
			return (bool) call_user_func( $this->nonce_checker, $nonce );
		}
		return true;
	}

	/**
	 * Where the request came from: a FetchContext constant.
	 *
	 * When the site's origins come from a callable the result is not cached: the callable is cheap, and the
	 * first caller may run early (on a probe or 404 path, at plugins_loaded) before filters registered later
	 * (theme functions.php, init) are in place; a login request in the same process must see those.
	 */
	public function fetch_context(): string {
		if ( null !== $this->fetch_context ) {
			return $this->fetch_context;
		}
		$lazy    = $this->own_hosts instanceof \Closure;
		$hosts   = $lazy ? (array) call_user_func( $this->own_hosts ) : (array) $this->own_hosts;
		$context = FetchContext::from_server( array_merge( $this->server, array( 'REQUEST_METHOD' => $this->method ) ), array_values( array_filter( array_map( 'strval', $hosts ) ) ) );
		if ( ! $lazy ) {
			$this->fetch_context = $context;
		}
		return $context;
	}

	/** Is this a visitor's own top-level navigation (Sec-Fetch-Mode navigate, destination document)? */
	public function is_navigation(): bool {
		return FetchContext::is_navigation( $this->server );
	}

	/** Is this a page's own image, script, stylesheet or font load for a file of that kind? Never counted. */
	public function is_exempt_subresource(): bool {
		return FetchContext::is_subresource( $this->server, $this->path );
	}

	/**
	 * Did another site (or, for same-site, a mislabelled "subresource" load) cause this request?
	 *
	 * Such requests are counted in a separate bucket with a higher limit, so a page that
	 * embeds a probe URL can't ban a visitor quickly, but a scanner that sets the header still gets banned.
	 */
	public function is_foreign_fetch(): bool {
		// A visitor's own top-level navigation is never foreign: one link click can't ban anyone, and a scanner that
		// forges navigation headers on every request lands in the normal bucket and earns the site-wide ban.
		if ( $this->is_navigation() ) {
			return false;
		}
		$context = $this->fetch_context();
		if ( FetchContext::CROSS_SITE === $context ) {
			return true;
		}
		// A "subresource" load whose file type doesn't fit its destination (a probe labelled as an image) is foreign only when
		// the browser also says it didn't come from this site. Same-origin loads of dynamic scripts and styles
		// (load-scripts.php, CAPTCHA images) are the visitor's own.
		return FetchContext::SAME_SITE === $context && FetchContext::is_subresource_load( $this->server ) && ! $this->is_exempt_subresource();
	}

	/**
	 * Does this look like a credentials request that another site started?
	 *
	 * "Cross-site" and "same-site" both count (sibling subdomains, subdomain multisite), unless the
	 * Origin names this site or an allowed origin, which FetchContext has already turned into "same-origin".
	 * Applies to any method: a Basic-auth GET carries credentials too.
	 */
	public function is_foreign_credentials_request(): bool {
		$context = $this->fetch_context();
		return FetchContext::CROSS_SITE === $context || FetchContext::SAME_SITE === $context;
	}

	/** Is this a request to wp-login.php (including /wp-login.php/extra PATH_INFO)? */
	public function is_login(): bool {
		return self::has_segment( $this->path, '/wp-login.php' );
	}

	/**
	 * Is this a request that core authenticates with application passwords: XML-RPC, or a REST call?
	 *
	 * A rest_route on admin-ajax.php, wp-login.php or another PHP file never reaches the REST server,
	 * so credentials there mean nothing. Pretty (/wp-json/...) and front-controller (/?rest_route=,
	 * index.php) paths count.
	 */
	public function is_api_auth_request(): bool {
		if ( $this->is_xmlrpc() ) {
			return true;
		}
		if ( '' === $this->rest_route() ) {
			return false;
		}
		return false !== strpos( $this->path, '/wp-json/' ) || false === strpos( $this->path, '.php' ) || '/index.php' === substr( $this->path, -10 );
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
