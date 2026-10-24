<?php
/**
 * Refuses, and bans, visitors who probe for secrets and backups.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;
use WPBouncer\Storage\CounterStoreInterface;

defined( 'ABSPATH' ) || exit;

/**
 * Scanners ask for files that leak secrets if they exist: .env, .git/config,
 * wp-config.php backups, database dumps, debug.log, phpinfo pages, web shells.
 *
 * A file that really exists is served by the web server before WordPress
 * runs, so when one of these requests reaches the plugin, the file isn't
 * there and the visitor is guessing. No real visitor asks for /.git/config,
 * so one probe is enough to ban the IP for a while.
 *
 * Settings:
 * - enabled (bool)
 * - ban_minutes (int): how long a prober is refused everywhere; 0 refuses only the probe.
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

	/** Real WordPress files that look like probes but aren't secret. */
	private const NOT_PROBES = array( '/wp-config.php', '/wp-config-sample.php' );

	/**
	 * Counter store.
	 *
	 * @var CounterStoreInterface
	 */
	private CounterStoreInterface $store;

	/**
	 * Set up the SensitiveFileRule.
	 *
	 * @param array<string, mixed>  $settings Rule settings.
	 * @param CounterStoreInterface $store    Ban storage.
	 */
	public function __construct( array $settings, CounterStoreInterface $store ) {
		parent::__construct( $settings );
		$this->store = $store;
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

		$ban_minutes = $request->can_be_banned() ? max( 0, (int) $this->setting( 'ban_minutes', 60 ) ) : 0;
		if ( $ban_minutes > 0 && null !== $this->store->get( self::ban_key( $ip ) ) ) {
			return $this->deny( 'Banned after probing for sensitive files' );
		}

		$what = $this->match( $request->path() );
		if ( null === $what ) {
			return null;
		}
		if ( $ban_minutes > 0 ) {
			$this->store->set( self::ban_key( $ip ), 1, $ban_minutes * 60 );
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
	 * Store key for an IP's ban.
	 *
	 * @param string $ip Client IP.
	 */
	public static function ban_key( string $ip ): string {
		return 'sf_ban:' . $ip;
	}
}
