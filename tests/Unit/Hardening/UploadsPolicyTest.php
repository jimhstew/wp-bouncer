<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Hardening;

use PHPUnit\Framework\TestCase;
use WPBouncer\Hardening\UploadsPolicy;

/**
 * @covers \WPBouncer\Hardening\UploadsPolicy
 */
final class UploadsPolicyTest extends TestCase {

	/** @var string[] */
	private array $tmp = array();

	protected function tearDown(): void {
		foreach ( $this->tmp as $f ) {
			@unlink( $f );
		}
	}

	private function file( string $contents ): string {
		$path        = tempnam( sys_get_temp_dir(), 'wpb' );
		$this->tmp[] = $path;
		file_put_contents( $path, $contents );
		return $path;
	}

	/** @return array<string, array{0: string}> */
	public static function dangerous(): array {
		$out = array();
		foreach ( array( 'shell.php', 'SHELL.PHP', 'photo.php.jpg', 'x.phtml', 'x.php5', 'x.phar', 'x.pht', 'a.shtml', 'run.cgi', 'x.pl', 'x.py', '.htaccess', '.user.ini', 'php.ini', 'web.config', 'C:\\fakepath\\evil.php', '../../evil.php' ) as $n ) {
			$out[ $n ] = array( $n );
		}
		return $out;
	}

	/** @return array<string, array{0: string}> */
	public static function safe(): array {
		$out = array();
		foreach ( array( 'photo.jpg', 'report.pdf', 'php-tutorial.pdf', 'my.photo.png', 'phpinfo-screenshot.png', 'archive.zip', 'notes.txt', 'data.csv', 'php', 'iniconfig.txt' ) as $n ) {
			$out[ $n ] = array( $n );
		}
		return $out;
	}

	/** @dataProvider dangerous */
	public function test_dangerous_names( string $name ): void {
		$this->assertNotNull( UploadsPolicy::dangerous_name( $name ), $name );
	}

	/** @dataProvider safe */
	public function test_safe_names( string $name ): void {
		$this->assertNull( UploadsPolicy::dangerous_name( $name ), $name );
	}

	public function test_reason_names_the_extension(): void {
		$this->assertSame( 'script extension .php', UploadsPolicy::dangerous_name( 'cat.php.gif' ) );
	}

	public function test_finds_php_in_a_fake_image(): void {
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( "GIF89a\x01\x00<?php system(\$_GET['c']); ?>" ) ) );
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( '<?PHP echo 1;' ) ) );
	}

	public function test_finds_short_echo_tag(): void {
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( "GIF89a<?= \$_GET['c'] ?>" ) ) );
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( str_repeat( 'a', 1048576 - 1 ) . '<?=$x' ) ) );
	}

	public function test_bare_echo_open_in_binary_data_is_not_php(): void {
		$this->assertFalse( UploadsPolicy::has_php_tag( "\x01<?=\xff\x02", true ) );
		$this->assertFalse( UploadsPolicy::has_php_tag( '<?=', true ) );
		$this->assertFalse( UploadsPolicy::has_php_tag( '<?=', false ) );
		$this->assertFalse( UploadsPolicy::has_php_tag( '<?=>', false ) );
	}

	/** @dataProvider echo_tag_evasions */
	public function test_echo_tag_evasions_are_found( string $code ): void {
		$this->assertTrue( UploadsPolicy::has_php_tag( $code, false ), 'text tier' );
		$this->assertTrue( UploadsPolicy::has_php_tag( "\x01\x02" . $code . "\xff\x00", true ), 'media tier' );
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( "GIF89a\x01\x00" . $code ), 52428800, 'a.gif' ), 'in a GIF named .gif' );
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( "GIF89a\x01\x00" . $code ) ), 'in a GIF, name unknown' );
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( "\xff\xd8\xff\xe0" . str_repeat( "\x01", 100 ) . $code . "\xff\x00\x00" ), 52428800, 'a.jpg' ), 'in a JPEG' );
	}

	public static function echo_tag_evasions(): array {
		return array(
			'variable'        => array( '<?= $x ?>' ),
			'function call'   => array( '<?=system($_GET[0]);' ),
			'backticks'       => array( '<?=`id`?>' ),
			'statement first' => array( '<?=1;system($_GET[0])?>' ),
			'comment first'   => array( '<?=/**/system($_GET[0]);' ),
			'silenced'        => array( '<?=@$x;' ),
			'tilde'           => array( '<?=~"\x9e\x8c"();' ),
			'namespaced'      => array( '<?=  \\Foo\\bar ( 1 );' ),
		);
	}

	/** @dataProvider relaxed_media */
	public function test_media_needs_extension_and_signature_to_agree( string $head, string $name, bool $expected ): void {
		$this->assertSame( $expected, UploadsPolicy::is_binary_media( $head, $name ), $name );
	}

	public static function relaxed_media(): array {
		return array(
			'jpeg'                    => array( "\xff\xd8\xff\xe0", 'photo.JPG', true ),
			'png'                     => array( "\x89PNG\r\n\x1a\n", 'a.png', true ),
			'gif'                     => array( 'GIF89a', 'a.gif', true ),
			'mp4'                     => array( "\x00\x00\x00\x18ftypmp42", 'v.mp4', true ),
			'webp'                    => array( "RIFF\x00\x00\x00\x00WEBP", 'v.webp', true ),
			'zip'                     => array( "PK\x03\x04", 'a.zip', true ),
			'pdf'                     => array( '%PDF-1.7', 'a.pdf', true ),
			'mismatch: png as jpg'    => array( "\x89PNG", 'a.jpg', false ),
			'php with gif magic'      => array( 'GIF89a', 'shell.php', false ),
			'phtml with jpeg magic'   => array( "\xff\xd8\xff", 'x.phtml', false ),
			'phar'                    => array( "PK\x03\x04", 'x.phar', false ),
			'php3'                    => array( 'GIF89a', 'x.php3', false ),
			'double extension'        => array( 'GIF89a', 'x.php.gif', false ),
			'double extension, other' => array( 'GIF89a', 'x.gif.php', false ),
			'unknown extension'       => array( 'GIF89a', 'x.dat', false ),
			'no extension'            => array( 'GIF89a', 'x', false ),
			'no name'                 => array( 'GIF89a', '', false ),
			'htaccess'                => array( 'GIF89a', '.htaccess', false ),
			'text'                    => array( '<?xml version', 'a.svg', false ),
		);
	}

	public function test_a_media_signature_alone_does_not_relax_the_echo_tag_rule(): void {
		// A GIF header on a file called .php (or .dat) is scanned strictly: any code after "<?=" counts.
		$data = "GIF89a\x01<?=\xff@ \x00";
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( $data ), 52428800, 'shell.php' ) );
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( $data ), 52428800, 'x.dat' ) );
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( $data ) ) );
		$this->assertFalse( UploadsPolicy::contains_php( $this->file( $data ), 52428800, 'x.gif' ), 'a real GIF is scanned with the relaxed rule' );
	}

	public function test_context_after_the_tag_is_found_across_chunks(): void {
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( str_repeat( 'a', 1048576 - 3 ) . '<?=' . str_repeat( ' ', 10 ) . '$x' ) ) );
	}

	public function test_8mb_of_seeded_random_bytes_has_no_match_with_or_without_a_media_header(): void {
		$data = '';
		for ( $i = 0; $i < 262144; $i++ ) {
			$data .= hash( 'sha256', 'wpb-seed-' . $i, true );
		}
		$this->assertSame( 8388608, strlen( $data ) );
		$this->assertFalse( UploadsPolicy::contains_php( $this->file( "\xff\xd8\xff" . $data ), 52428800, 'photo.jpg' ) );
		$this->assertFalse( UploadsPolicy::has_php_tag( $data, true ) );
	}

	public function test_clean_files_pass(): void {
		$this->assertFalse( UploadsPolicy::contains_php( $this->file( "\x89PNG\r\n\x1a\n" . str_repeat( 'x', 5000 ) ) ) );
		$this->assertFalse( UploadsPolicy::contains_php( $this->file( '<?xml version="1.0"?><svg></svg>' ) ) );
		$this->assertFalse( UploadsPolicy::contains_php( '/no/such/file' ) );
	}

	public function test_tag_split_across_chunks_is_found(): void {
		// The read size is 1 MiB; put "<?php" across the boundary.
		$this->assertTrue( UploadsPolicy::contains_php( $this->file( str_repeat( 'a', 1048576 - 2 ) . '<?php' ) ) );
	}

	public function test_scan_stops_at_the_limit(): void {
		$path = $this->file( str_repeat( 'a', 2000 ) . '<?php' );
		$this->assertFalse( UploadsPolicy::contains_php( $path, 1000 ) );
		$this->assertTrue( UploadsPolicy::contains_php( $path ) );
	}

	public function test_htaccess_block_denies_scripts_without_php_flag(): void {
		$text = implode( "\n", UploadsPolicy::htaccess_lines() );
		$this->assertStringContainsString( 'Require all denied', $text );
		$this->assertStringContainsString( 'Deny from all', $text );
		$this->assertStringNotContainsString( 'php_flag', $text, 'php_flag breaks PHP-FPM servers' );
		$this->assertStringContainsString( 'php[0-9]?', $text );
	}

	public function test_htaccess_regex_matches_the_same_names(): void {
		preg_match( '/<FilesMatch "(.+)">/', implode( "\n", UploadsPolicy::htaccess_lines() ), $m );
		$re = '/' . str_replace( '(?i:', '(?:', $m[1] ) . '/i';
		foreach ( array( 'a.php', 'a.PHP', 'a.php7', 'a.phtml', 'a.phar' ) as $n ) {
			$this->assertSame( 1, preg_match( $re, $n ), $n );
		}
		foreach ( array( 'a.jpg', 'a.php.jpg.txt', 'php.png' ) as $n ) {
			$this->assertSame( 0, preg_match( $re, $n ), $n );
		}
	}

	public function test_nginx_snippet(): void {
		$this->assertStringContainsString( 'deny all;', UploadsPolicy::nginx_snippet() );
		$this->assertStringContainsString( '/wp-content/uploads/', UploadsPolicy::nginx_snippet() );
	}

	public function test_probe_interpretation(): void {
		$this->assertSame( 'unprotected', UploadsPolicy::interpret_probe( 200, 'wpb-php-ran', 'wpb-php-ran' ) );
		$this->assertSame( 'protected', UploadsPolicy::interpret_probe( 200, "<?php echo 'wpb-php-' . 'ran';", 'wpb-php-ran' ) );
		$this->assertSame( 'protected', UploadsPolicy::interpret_probe( 403, 'Forbidden', 'wpb-php-ran' ) );
		$this->assertSame( 'protected', UploadsPolicy::interpret_probe( 401, '', 'wpb-php-ran' ) );
		$this->assertSame( 'unknown', UploadsPolicy::interpret_probe( 404, '', 'wpb-php-ran' ) );
		$this->assertSame( 'unknown', UploadsPolicy::interpret_probe( 500, '', 'wpb-php-ran' ) );
		$this->assertSame( 'unknown', UploadsPolicy::interpret_probe( 0, '', 'wpb-php-ran' ) );
		$this->assertSame( 'unknown', UploadsPolicy::interpret_probe( 200, '<html>a page</html>', 'wpb-php-ran' ) );
	}

	public function test_serving_check_interpretation(): void {
		$this->assertSame( 'ok', UploadsPolicy::interpret_serving( 200, 'wpb-ok', 'wpb-ok' ) );
		$this->assertSame( 'broken', UploadsPolicy::interpret_serving( 500, 'Internal Server Error', 'wpb-ok' ) );
		$this->assertSame( 'broken', UploadsPolicy::interpret_serving( 503, '', 'wpb-ok' ) );
		$this->assertSame( 'unknown', UploadsPolicy::interpret_serving( 502, '', 'wpb-ok' ), 'a proxy error is not the block\'s fault' );
		$this->assertSame( 'unknown', UploadsPolicy::interpret_serving( 504, '', 'wpb-ok' ) );
		$this->assertSame( 'unknown', UploadsPolicy::interpret_serving( 200, 'a login page', 'wpb-ok' ) );
		$this->assertSame( 'unknown', UploadsPolicy::interpret_serving( 403, '', 'wpb-ok' ) );
		$this->assertSame( 'unknown', UploadsPolicy::interpret_serving( 0, '', 'wpb-ok' ) );
	}
}
