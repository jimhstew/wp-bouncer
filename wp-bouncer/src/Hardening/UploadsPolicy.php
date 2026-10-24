<?php
/**
 * What "no PHP in uploads" means, as pure functions.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * The commonest way a WordPress site gets backdoored: a weak upload form in
 * some plugin lets an attacker put a .php file in wp-content/uploads, and
 * then they run it by visiting its URL. Two defences:
 *
 * 1. Stop the web server running PHP from the uploads folder (htaccess_lines()).
 *    This works whichever plugin let the file in.
 * 2. Refuse uploads through WordPress's own upload handling that are PHP
 *    in disguise (dangerous_name(), contains_php()).
 *
 * No WordPress calls here; UploadsGuard does the file writing and hooking.
 */
final class UploadsPolicy {

	/** Extensions the web server might run as code. */
	public const SCRIPT_EXTENSIONS = array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps', 'pgif', 'shtml', 'cgi', 'pl', 'py', 'asp', 'aspx', 'jsp' );

	/** File names that change how the server treats the folder. */
	private const SERVER_FILES = array( '.htaccess', '.user.ini', 'php.ini', 'web.config', '.htpasswd' );

	/** Marker name for the block written into uploads/.htaccess. */
	public const MARKER = 'WP Bouncer';

	/**
	 * Lines for uploads/.htaccess (Apache 2.2/2.4 and LiteSpeed).
	 *
	 * Uses access rules only. "php_flag engine off" is avoided on purpose:
	 * it causes a 500 error on servers that run PHP through PHP-FPM.
	 *
	 * @return string[]
	 */
	public static function htaccess_lines(): array {
		return array(
			'# Do not run scripts uploaded to this folder.',
			'<FilesMatch "\.(?i:php[0-9]?|phtml|pht|phar|phps|pgif|shtml|cgi|pl|py|asp|aspx|jsp)$">',
			'	<IfModule mod_authz_core.c>',
			'		Require all denied',
			'	</IfModule>',
			'	<IfModule !mod_authz_core.c>',
			'		Order allow,deny',
			'		Deny from all',
			'	</IfModule>',
			'</FilesMatch>',
		);
	}

	/** The same protection for nginx, which ignores .htaccess. */
	public static function nginx_snippet(): string {
		return "location ~* ^/wp-content/uploads/.*\\.(php[0-9]?|phtml|pht|phar|phps|pgif|shtml|cgi|pl|py|asp|aspx|jsp)$ {\n    deny all;\n}";
	}

	/**
	 * Why a file name is dangerous, or null if it's fine.
	 *
	 * Catches double extensions such as "photo.php.jpg" as well as plain
	 * ".php", since some server setups run any file with ".php" anywhere in
	 * its name.
	 *
	 * @param string $name Uploaded file name.
	 */
	public static function dangerous_name( string $name ): ?string {
		$name = strtolower( trim( basename( str_replace( '\\', '/', $name ) ) ) );
		if ( in_array( $name, self::SERVER_FILES, true ) ) {
			return 'server configuration file (' . $name . ')';
		}
		$parts = explode( '.', $name );
		array_shift( $parts ); // The part before the first dot isn't an extension.
		foreach ( $parts as $ext ) {
			if ( in_array( $ext, self::SCRIPT_EXTENSIONS, true ) ) {
				return 'script extension .' . $ext;
			}
		}
		return null;
	}

	/**
	 * Does the file contain a PHP opening tag ("<?php", any case)?
	 *
	 * Reads in chunks with an overlap so a tag split across two chunks is
	 * still found. Files larger than $max_bytes are only checked up to that point.
	 *
	 * @param string $path      File to check.
	 * @param int    $max_bytes How much to read.
	 */
	public static function contains_php( string $path, int $max_bytes = 52428800 ): bool {
		$handle = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions -- a failed open is handled by the false check below; plugin-owned local file, WP_Filesystem cannot stream.
		if ( false === $handle ) {
			return false;
		}
		$tail  = '';
		$read  = 0;
		$found = false;
		while ( ! feof( $handle ) && $read < $max_bytes ) {
			$chunk = fread( $handle, max( 1, min( 1048576, $max_bytes - $read ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reads only the first bytes of a local file with a size cap; WP_Filesystem has no partial read.
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			$read += strlen( $chunk );
			if ( false !== stripos( $tail . $chunk, '<?php' ) ) {
				$found = true;
				break;
			}
			$tail = substr( $chunk, -4 );
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reads only the first bytes of a local file with a size cap; WP_Filesystem has no partial read.
		return $found;
	}

	/**
	 * Interpret the result of requesting a plain text file placed in uploads,
	 * with the .htaccess block in place.
	 *
	 * @param int    $status   HTTP status (0 when the request failed).
	 * @param string $body     Response body.
	 * @param string $expected The file's contents.
	 * @return string 'ok' (the file loaded), 'broken' (a 5xx: the server
	 *                rejects the block) or 'unknown'.
	 */
	public static function interpret_serving( int $status, string $body, string $expected ): string {
		if ( 200 === $status && false !== strpos( $body, $expected ) ) {
			return 'ok';
		}
		return $status >= 500 && $status <= 599 ? 'broken' : 'unknown';
	}

	/**
	 * Interpret the result of requesting a test script placed in uploads.
	 *
	 * @param int    $status HTTP status (0 when the request failed).
	 * @param string $body   Response body.
	 * @param string $marker Text the script prints only if PHP ran it.
	 * Only a refusal (401/403) or the file coming back as plain text counts as
	 * protected. Anything else (a 404, a 500, a redirect) proves nothing.
	 *
	 * @return string 'protected', 'unprotected' or 'unknown'.
	 */
	public static function interpret_probe( int $status, string $body, string $marker ): string {
		if ( 200 === $status ) {
			if ( false !== strpos( $body, $marker ) ) {
				return 'unprotected';
			}
			// The script's own source: the server handed it out as text instead of running it.
			return false !== stripos( $body, '<?php' ) ? 'protected' : 'unknown';
		}
		if ( 401 === $status || 403 === $status ) {
			return 'protected';
		}
		return 'unknown';
	}
}
