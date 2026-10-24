<?php
/**
 * An EnvironmentInterface you can set up by hand.
 *
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Support;

use WPBouncer\Environment\EnvironmentInterface;

/**
 * Plain arrays for ini values, constants and "inside the web root" answers.
 */
final class FakeEnvironment implements EnvironmentInterface {

	/**
	 * Create one.
	 *
	 * @param string                $php        PHP version.
	 * @param string                $db         Database server string.
	 * @param array<string, string> $ini        ini values (missing = unknown directive).
	 * @param array<string, mixed>  $constants  Defined constants.
	 * @param array<string, bool>   $inside     Path => inside the web root (missing = cannot tell).
	 * @param string                $sapi       SAPI.
	 * @param bool                  $https      HTTPS request.
	 * @param array<string, int>    $files      Path => size in bytes.
	 */
	public function __construct(
		public string $php = '8.3.12',
		public string $db = '10.11.6-MariaDB',
		public array $ini = array(),
		public array $constants = array(),
		public array $inside = array(),
		public string $sapi = 'fpm-fcgi',
		public bool $https = true,
		public array $files = array()
	) {
	}

	/** {@inheritDoc} */
	public function php_version(): string {
		return $this->php;
	}

	/** {@inheritDoc} */
	public function db_server_info(): string {
		return $this->db;
	}

	/** {@inheritDoc} */
	public function sapi(): string {
		return $this->sapi;
	}

	/**
	 * Fake answer.
	 *
	 * @param string $name Argument.
	 */
	public function ini( string $name ): string|false {
		return $this->ini[ $name ] ?? false;
	}

	/**
	 * Fake answer.
	 *
	 * @param string $name Argument.
	 */
	public function constant( string $name ): mixed {
		return $this->constants[ $name ] ?? null;
	}

	/** {@inheritDoc} */
	public function is_https(): bool {
		return $this->https;
	}

	/**
	 * Fake answer.
	 *
	 * @param string $path Argument.
	 */
	public function inside_web_root( string $path ): ?bool {
		return $this->inside[ $path ] ?? null;
	}

	/**
	 * Fake file size.
	 *
	 * @param string $path Argument.
	 */
	public function file_size( string $path ): ?int {
		return $this->files[ $path ] ?? null;
	}
}
