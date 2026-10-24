<?php
/**
 * Refuses, and bans, visitors who probe for secrets and backups.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;
use WPBouncer\Settings;
use WPBouncer\Storage\AtomicCounterInterface;
use WPBouncer\Storage\CounterStoreInterface;

defined( 'ABSPATH' ) || exit;

/**
 * Scanners ask for files that leak secrets if they exist: .env, .git/config,
 * wp-config.php backups, database dumps, debug.log, phpinfo pages, web shells.
 *
 * A file that really exists is served by the web server before WordPress
 * runs, so when one of these requests reaches the plugin, the file isn't
 * there and the visitor is guessing. Every probe is refused; a second one
 * within ten minutes bans the IP for a while. A probe that another site's
 * page caused (Sec-Fetch-Site: cross-site, or an image/script request) never counts.
 *
 * Settings:
 * - enabled (bool)
 * - ban_minutes (int): how long a prober is refused everywhere (at most 1,440); 0 refuses only the probe.
 * - extra_paths (string[]): more path fragments to treat as probes, e.g. "/old-admin/".
 *
 * Logged-in administrators are never banned. Neither are loopback or proxy
 * addresses, nor anyone while the client IP can't be told apart from a shared
 * proxy (Request::can_be_banned()): such a probe is still refused, but no ban
 * is placed or enforced.
 */
final class SensitiveFileRule extends AbstractRule {

	public const ID = 'sensitive_files';

	/**
	 * Label => pattern, matched against the decoded, lowercased path.
	 */
	public const PATTERNS = array(
		'environment file'     => '#/\.env(\.[a-z0-9_.-]+)?$#',
		'version control data' => '#/\.(git|svn|hg|bzr|cvs)(/|$)#',
		'server config file'   => '#/\.(htpasswd|htaccess|user\.ini|npmrc|yarnrc|ftpconfig|ds_store|dockerenv|bash_history|mysql_history)$#',
		'hidden config folder' => '#/\.(aws|ssh|docker|vscode|idea|config)(/|$)#',
		'wp-config copy'       => '#/\.?wp-config[^/]+$#',
		'PHP file backup'      => '#\.php(\.(bak|backup|old|orig|save|swp|swo|tmp|txt|dist|1)|~|_bak|\.bk)$#',
		'database dump'        => '#\.(sql|sqlite|sqlite3)(\.(gz|zip|bz2|xz|7z|tar))?$#',
		'site backup archive'  => '#^/(backup|backups|site|website|www|wordpress|wp|db|database|dump|public_html|htdocs|html|web|data|old|archive|home|bak)\.(zip|rar|7z|tar|tgz|tar\.gz|gz|bz2)$#',
		'log file'             => '#/(debug|error|errors|php_errors?|access)\.log$|/error_log$#',
		'phpinfo page'         => '#/(phpinfo|php_info|info|pi)\.php$#',
		'database admin tool'  => '#/(adminer|phpmyadmin|pma|myadmin|sqladmin|mysqladmin)(/|[^/]*\.php$|$)#',
		'web shell'            => '#/(shell|wso|c99|r57|alfa|b374k|webshell|wp-shell|xmrlpc|cmd)\.php$#',
		'PHP in uploads'       => '#^/wp-content/uploads/.*\.(php\d?|phtml|phar|pht)$#',
		'PHPUnit exploit'      => '#/vendor/phpunit/|/eval-stdin\.php$#',
		'project manifest'     => '#^/(composer\.(json|lock)|package(-lock)?\.json|yarn\.lock|docker-compose\.ya?ml|dockerfile)$#',
		'server status page'   => '#^/server-(status|info)$#',
	);

	/** Probes inside the window that earn a site-wide ban. The first one is refused but does not ban. */
	public const BAN_AFTER = 2;

	/** The window for BAN_AFTER, in seconds. */
	public const BAN_WINDOW = 600;

	/** Real WordPress files that look like probes but aren't secret. */
	private const NOT_PROBES = array( '/wp-config.php', '/wp-config-sample.php' );

	/**
	 * Counter store.
	 *
	 * @var CounterStoreInterface
	 */
	private CounterStoreInterface $store;

	/**
	 * Atomic counter for the probe counts (falls back to the store's counter).
	 *
	 * @var AtomicCounterInterface|null
	 */
	private ?AtomicCounterInterface $counter;

	/**
	 * Set up the SensitiveFileRule.
	 *
	 * @param array<string, mixed>        $settings Rule settings (cross_site_probes: probes from another site's page that earn a ban, default 5).
	 * @param CounterStoreInterface       $store    Ban storage.
	 * @param AtomicCounterInterface|null $counter  Atomic counter for probe counts.
	 */
	public function __construct( array $settings, CounterStoreInterface $store, ?AtomicCounterInterface $counter = null ) {
		parent::__construct( $settings );
		$this->store   = $store;
		$this->counter = $counter;
	}

	/** {@inheritDoc} */
	public function id(): string {
		return self::ID;
	}

	/**
	 * Inspect the request.
	 *
	 * @param Request $request Incoming request.
	 * @return Verdict|null A Verdict to refuse the request, or null to let it through.
	 */
	public function inspect( Request $request ): ?Verdict {
		$ip = $request->key_ip();
		if ( '' === $ip || $request->is_trusted() ) {
			return null;
		}

		$ban_minutes = $request->can_be_banned() ? min( Settings::MAX_BAN_MINUTES, max( 0, (int) $this->setting( 'ban_minutes', 60 ) ) ) : 0;
		if ( $ban_minutes > 0 && null !== $this->store->get( self::ban_key( $ip ) ) ) {
			return $this->deny( 'Banned after probing for sensitive files' );
		}

		// After foreign probes passed their limit, requests that another site's page causes are refused for the ban period.
		// Requests the visitor makes themselves (same-origin, no headers, link clicks) are untouched, so a hostile
		// page that fires probes at a visitor can't lock the visitor out of the site.
		if ( $ban_minutes > 0 && $request->is_foreign_fetch() && null !== $this->store->get( self::foreign_ban_key( $ip ) ) ) {
			return $this->deny( 'Requests from another site refused after repeated probes' );
		}

		$what = $this->match( $request->path() );
		if ( null === $what ) {
			return null;
		}
		// A probe that another site's page caused (an image tag, say) is counted in its own bucket with a higher
		// limit, so it can't ban a visitor quickly while a scanner that fakes the header is still banned in the end.
		// A real image/script/style load of a file of that kind is not counted at all.
		if ( $ban_minutes > 0 && ! $request->is_exempt_subresource() ) {
			$foreign = $request->is_foreign_fetch();
			$key     = $foreign ? self::foreign_probe_key( $ip ) : self::probe_key( $ip );
			$limit   = $foreign ? max( self::BAN_AFTER, (int) $this->setting( 'cross_site_probes', 5 ) ) : self::BAN_AFTER;
			$probes  = null !== $this->counter ? $this->counter->add_or_increment( $key, self::BAN_WINDOW ) : $this->store->increment( $key, self::BAN_WINDOW );
			if ( $probes >= $limit ) {
				// Foreign probes never place the site-wide ban (a hostile page could aim them at a visitor);
				// they only close the door to further foreign requests.
				$this->store->set( $foreign ? self::foreign_ban_key( $ip ) : self::ban_key( $ip ), 1, $ban_minutes * 60 );
				null !== $this->counter ? $this->counter->delete( $key ) : $this->store->delete( $key );
			}
		}
		return $this->deny( 'Probe for a sensitive file (' . $what . ')' );
	}

	/**
	 * What kind of probe a path is, or null if it isn't one.
	 *
	 * @param string $path Normalised path (decoded, lowercase).
	 */
	public function match( string $path ): ?string {
		if ( 0 === strpos( $path, '/.well-known/' ) || in_array( $path, self::NOT_PROBES, true ) ) {
			return null;
		}
		// The uploads "Test now" script. The site requests it itself; if the
		// server ever hands that request to WordPress, it must not ban itself.
		if ( preg_match( '#^/wp-content/uploads/wp-bouncer-test-[a-z0-9]+\.php$#', $path ) ) {
			return null;
		}
		foreach ( self::PATTERNS as $label => $pattern ) {
			if ( preg_match( $pattern, $path ) ) {
				return $label;
			}
		}
		foreach ( (array) $this->setting( 'extra_paths', array() ) as $fragment ) {
			$fragment = strtolower( trim( (string) $fragment ) );
			if ( '' !== $fragment && false !== strpos( $path, $fragment ) ) {
				return 'custom path ' . $fragment;
			}
		}
		return null;
	}

	/**
	 * Store key for an IP's probe counter.
	 *
	 * @param string $ip Client IP.
	 */
	public static function probe_key( string $ip ): string {
		return 'sf_probe:' . $ip;
	}

	/**
	 * Store key for an IP's counter of probes that another site's page caused.
	 *
	 * @param string $ip Client IP.
	 */
	public static function foreign_probe_key( string $ip ): string {
		return 'sf_probe_x:' . $ip;
	}

	/**
	 * Store key for the refusal of foreign requests from an IP.
	 *
	 * @param string $ip Client IP.
	 */
	public static function foreign_ban_key( string $ip ): string {
		return 'sf_xban:' . $ip;
	}

	/**
	 * Store key for an IP's ban.
	 *
	 * @param string $ip Client IP.
	 */
	public static function ban_key( string $ip ): string {
		return 'sf_ban:' . $ip;
	}
}
