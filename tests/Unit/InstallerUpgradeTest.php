<?php
namespace WPBouncer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPBouncer\Installer;

final class InstallerUpgradeTest extends TestCase {

	public function test_redaction_only_starts_below_version_3(): void {
		$this->assertTrue( Installer::needs_redaction( false ), 'fresh install' );
		$this->assertTrue( Installer::needs_redaction( '1' ) );
		$this->assertTrue( Installer::needs_redaction( '2' ) );
		$this->assertFalse( Installer::needs_redaction( '3' ), 'the 3 to 4 upgrade must not restart it' );
		$this->assertFalse( Installer::needs_redaction( '4' ) );
		$this->assertSame( '4', Installer::DB_VERSION );
	}
}
