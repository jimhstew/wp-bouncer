<?php
/**
 * @package WPBouncer\Tests
 */

namespace WPBouncer\Tests\Unit\Firewall;

use PHPUnit\Framework\TestCase;
use WPBouncer\Firewall\Firewall;
use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Rules\RuleInterface;
use WPBouncer\Tests\Support\MemoryStore;
use WPBouncer\Tests\Support\FakeGeo;
use WPBouncer\Tests\Support\FrozenClock;
use WPBouncer\Tests\Support\MemoryBlockLog;
use WPBouncer\Tests\Support\RecordingResponder;
use WPBouncer\Tests\Support\Requests;

/**
 * @covers \WPBouncer\Firewall\Firewall
 */
final class FirewallTest extends TestCase {

	private MemoryBlockLog $log;
	private RecordingResponder $responder;
	private FrozenClock $clock;
	private MemoryStore $store;

	protected function setUp(): void {
		$this->log       = new MemoryBlockLog();
		$this->responder = new RecordingResponder();
		$this->clock     = new FrozenClock();
		$this->store     = new MemoryStore( $this->clock );
	}

	/**
	 * A rule stub that always objects (or never), counting calls.
	 */
	private function rule( string $id, bool $objects, bool $enabled = true ): RuleInterface {
		return new class( $id, $objects, $enabled ) implements RuleInterface {
			public int $calls = 0;
			private string $id;
			private bool $objects;
			private bool $enabled;

			public function __construct( string $id, bool $objects, bool $enabled ) {
				$this->id      = $id;
				$this->objects = $objects;
				$this->enabled = $enabled;
			}

			public function id(): string {
				return $this->id;
			}

			public function is_enabled(): bool {
				return $this->enabled;
			}

			public function inspect( Request $request ): ?Verdict {
				++$this->calls;
				return $this->objects ? new Verdict( $this->id, 'because ' . $this->id ) : null;
			}
		};
	}

	private function firewall( array $rules, array $allowlist = array(), bool $monitor = false ): Firewall {
		return new Firewall( $rules, $allowlist, $monitor, $this->log, $this->store, new FakeGeo( array( '203.0.113.10' => 'NL' ) ) );
	}

	public function test_clean_request_passes(): void {
		$fw = $this->firewall( array( $this->rule( 'a', false ), $this->rule( 'b', false ) ) );
		$this->assertNull( $fw->handle( Requests::make(), $this->responder, 'no' ) );
		$this->assertEmpty( $this->responder->denials );
		$this->assertEmpty( $this->log->entries );
	}

	public function test_first_objection_wins_and_later_rules_are_skipped(): void {
		$a  = $this->rule( 'a', false );
		$b  = $this->rule( 'b', true );
		$c  = $this->rule( 'c', true );
		$fw = $this->firewall( array( $a, $b, $c ) );

		$verdict = $fw->handle( Requests::make(), $this->responder, 'Go away' );

		$this->assertSame( 'b', $verdict->rule() );
		$this->assertSame( 1, $a->calls );
		$this->assertSame( 1, $b->calls );
		$this->assertSame( 0, $c->calls, 'rules after the first objection must not run' );
		$this->assertCount( 1, $this->responder->denials );
		$this->assertSame( 'Go away', $this->responder->denials[0]['message'] );
		$this->assertSame( 1, $this->responder->denials[0]['reference'], 'reference is the log row id' );
	}

	public function test_disabled_rules_are_not_run(): void {
		$off = $this->rule( 'off', true, false );
		$fw  = $this->firewall( array( $off ) );
		$this->assertNull( $fw->evaluate( Requests::make() ) );
		$this->assertSame( 0, $off->calls );
	}

	public function test_block_is_logged_with_request_details(): void {
		$fw = $this->firewall( array( $this->rule( 'waf', true ) ) );
		$fw->handle(
			Requests::make(
				array(
					'method' => 'POST',
					'uri'    => '/evil?x=1',
					'ua'     => 'curl/8',
				)
			),
			$this->responder,
			''
		);

		$entry = $this->log->entries[0];
		$this->assertSame( '203.0.113.10', $entry['ip'] );
		$this->assertSame( 'NL', $entry['country'] );
		$this->assertSame( 'waf', $entry['rule'] );
		$this->assertSame( BlockLogInterface::ACTION_BLOCKED, $entry['action'] );
		$this->assertSame( 'because waf', $entry['reason'] );
		$this->assertSame( 'POST', $entry['method'] );
		$this->assertSame( '/evil?x=1', $entry['uri'] );
		$this->assertSame( 'curl/8', $entry['user_agent'] );
	}

	public function test_monitor_mode_logs_but_does_not_block(): void {
		$fw      = $this->firewall( array( $this->rule( 'a', true ) ), array(), true );
		$verdict = $fw->handle( Requests::make(), $this->responder, '' );

		$this->assertNotNull( $verdict );
		$this->assertEmpty( $this->responder->denials );
		$this->assertSame( BlockLogInterface::ACTION_MONITORED, $this->log->entries[0]['action'] );
	}

	public function test_allowlisted_ip_skips_all_rules(): void {
		$rule = $this->rule( 'a', true );
		$fw   = $this->firewall( array( $rule ), array( '203.0.113.0/24' ) );
		$this->assertNull( $fw->handle( Requests::make(), $this->responder, '' ) );
		$this->assertSame( 0, $rule->calls );
	}

	public function test_a_request_from_the_server_itself_is_exempt(): void {
		$fw = $this->firewall( array( $this->rule( 'a', true ) ) );
		$this->assertNull( $fw->evaluate( Requests::make( array( 'ip' => '127.0.0.1', 'local' => true ) ) ) );
		$this->assertNull( $fw->evaluate( Requests::make( array( 'ip' => '::1', 'local' => true ) ) ) );
	}

	public function test_loopback_ip_is_not_exempt_when_the_request_is_not_local(): void {
		// RT-04: a same-host proxy forwarding an outside visitor must not exempt that visitor.
		$fw = $this->firewall( array( $this->rule( 'a', true ) ) );
		$this->assertNotNull( $fw->evaluate( Requests::make( array( 'ip' => '127.0.0.1' ) ) ) );
		$this->assertNotNull( $fw->evaluate( Requests::make( array( 'ip' => '::1' ) ) ) );
	}

	public function test_an_allowlisted_loopback_address_is_still_exempt(): void {
		$fw = $this->firewall( array( $this->rule( 'a', true ) ), array( '127.0.0.1' ) );
		$this->assertNull( $fw->evaluate( Requests::make( array( 'ip' => '127.0.0.1' ) ) ) );
	}

	public function test_empty_ip_is_not_exempt(): void {
		$fw = $this->firewall( array( $this->rule( 'a', true ) ), array( '0.0.0.0/0' ) );
		$this->assertNotNull( $fw->evaluate( Requests::make( array( 'ip' => '' ) ) ) );
	}

	public function test_repeat_blocks_are_deduplicated_in_the_log(): void {
		$fw = $this->firewall( array( $this->rule( 'a', true ) ) );

		for ( $i = 0; $i < 5; $i++ ) {
			$fw->handle( Requests::make(), $this->responder, '' );
		}
		$this->assertCount( 5, $this->responder->denials, 'every request is still blocked' );
		$this->assertCount( 1, $this->log->entries, 'but only logged once per window' );
		$this->assertSame( 0, $this->responder->denials[1]['reference'] );

		$this->clock->advance( Firewall::LOG_DEDUPE_SECONDS );
		$fw->handle( Requests::make(), $this->responder, '' );
		$this->assertCount( 2, $this->log->entries, 'logged again after the window' );

		$fw->handle( Requests::make( array( 'ip' => '198.51.100.1' ) ), $this->responder, '' );
		$this->assertCount( 3, $this->log->entries, 'a different IP is logged separately' );
	}
}
