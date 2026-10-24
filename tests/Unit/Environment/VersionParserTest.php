<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Environment;

use PHPUnit\Framework\TestCase;
use WPBouncer\Environment\VersionParser;

/**
 * @covers \WPBouncer\Environment\VersionParser
 */
final class VersionParserTest extends TestCase {

	/**
	 * @dataProvider php_versions
	 */
	public function test_php( string $in, ?string $out ): void {
		$this->assertSame( $out, VersionParser::php( $in ) );
	}

	/** @return array<string, array{string, ?string}> */
	public static function php_versions(): array {
		return array(
			'plain'  => array( '8.3.12', '8.3' ),
			'distro' => array( '8.3.12-1ubuntu1', '8.3' ),
			'rc'     => array( '8.4.0RC1', '8.4' ),
			'two'    => array( '8.1', '8.1' ),
			'junk'   => array( 'banana', null ),
			'empty'  => array( '', null ),
		);
	}

	/**
	 * @dataProvider databases
	 * @param array{product: string, branch: string}|null $out Expected.
	 */
	public function test_database( string $in, ?array $out ): void {
		$this->assertSame( $out, VersionParser::database( $in ) );
	}

	/** @return array<string, array{string, ?array{product: string, branch: string}}> */
	public static function databases(): array {
		return array(
			'mariadb prefix' => array(
				'5.5.5-10.6.18-MariaDB-0ubuntu0.22.04.1',
				array(
					'product' => 'mariadb',
					'branch'  => '10.6',
				),
			),
			'mariadb log'    => array(
				'10.11.6-MariaDB-log',
				array(
					'product' => 'mariadb',
					'branch'  => '10.11',
				),
			),
			'mariadb 11'     => array(
				'11.4.2-MariaDB',
				array(
					'product' => 'mariadb',
					'branch'  => '11.4',
				),
			),
			'mysql distro'   => array(
				'8.0.36-0ubuntu0.22.04.1',
				array(
					'product' => 'mysql',
					'branch'  => '8.0',
				),
			),
			'mysql 8.4'      => array(
				'8.4.2',
				array(
					'product' => 'mysql',
					'branch'  => '8.4',
				),
			),
			'mysql 9'        => array(
				'9.1.0',
				array(
					'product' => 'mysql',
					'branch'  => '9.1',
				),
			),
			'percona'        => array(
				'8.0.36-28',
				array(
					'product' => 'mysql',
					'branch'  => '8.0',
				),
			),
			'aurora'         => array( '5.7.12 Aurora 2.11', null ),
			'azure'          => array( '8.0.36 Azure Database', null ),
			'tidb'           => array( '5.7.25-TiDB-v7.5.0', null ),
			'sqlite'         => array( '3.45.1 SQLite', null ),
			'garbage'        => array( 'who knows', null ),
			'empty'          => array( '', null ),
		);
	}
}
