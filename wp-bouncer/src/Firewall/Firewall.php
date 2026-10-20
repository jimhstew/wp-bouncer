<?php
/**
 * The bouncer: runs the rules and acts on the first objection.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Firewall;

use WPBouncer\Geo\GeoProviderInterface;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Rules\RuleInterface;
use WPBouncer\Storage\CounterStoreInterface;
use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Request flow:
 *
 *   1. Exempt? Allowlisted IPs and loopback (WP-Cron, health checks) pass.
 *   2. Run each enabled rule in order. The first Verdict wins.
 *   3. Log the verdict (repeats for the same IP and rule are suppressed for 60 s).
 *   4. Enforce mode: hand the verdict to the responder, which ends the request.
 *      Monitor mode: log only and let the request through.
 *
 * Rule order matters for performance: cheap checks (IP lists) run before
 * expensive ones (geo lookups, WAF regexes). See Plugin::build_rules().
 */
final class Firewall {

	/** Seconds during which repeat log entries for the same IP+rule are dropped. */
	public const LOG_DEDUPE_SECONDS = 60;

	/** @var RuleInterface[] */
	private array $rules;
	/** @var string[] */
	private array $allowlist;
	private bool $monitor;
	private BlockLogInterface $log;
	private CounterStoreInterface $store;
	private ?GeoProviderInterface $geo;

	/**
	 * @param RuleInterface[]           $rules     Rules in evaluation order.
	 * @param string[]                  $allowlist IPs / CIDRs that bypass every rule.
	 * @param bool                      $monitor   True for log-only mode.
	 * @param BlockLogInterface         $log       Block log.
	 * @param CounterStoreInterface     $store     Used for log de-duplication.
	 * @param GeoProviderInterface|null $geo       Adds the country to log entries.
	 */
	public function __construct( array $rules, array $allowlist, bool $monitor, BlockLogInterface $log, CounterStoreInterface $store, ?GeoProviderInterface $geo = null ) {
		$this->rules     = $rules;
		$this->allowlist = $allowlist;
		$this->monitor   = $monitor;
		$this->log       = $log;
		$this->store     = $store;
		$this->geo       = $geo;
	}

	/**
	 * Should this request skip every rule?
	 *
	 * @param Request $request Request.
	 */
	public function is_exempt( Request $request ): bool {
		$ip = $request->ip();
		if ( '' === $ip ) {
			return false;
		}
		return IpUtils::is_loopback( $ip ) || IpUtils::matches_any( $ip, $this->allowlist );
	}

	/**
	 * Run the rules without side effects other than the rules' own counters.
	 *
	 * @param Request $request Request.
	 * @return Verdict|null First objection, or null if every rule is happy.
	 */
	public function evaluate( Request $request ): ?Verdict {
		if ( $this->is_exempt( $request ) ) {
			return null;
		}
		foreach ( $this->rules as $rule ) {
			if ( ! $rule->is_enabled() ) {
				continue;
			}
			$verdict = $rule->inspect( $request );
			if ( null !== $verdict ) {
				return $verdict;
			}
		}
		return null;
	}

	/**
	 * Evaluate, log and (in enforce mode) refuse the request.
	 *
	 * @param Request            $request   Request.
	 * @param ResponderInterface $responder Sends the block page.
	 * @param string             $message   Message for the visitor.
	 * @return Verdict|null The verdict, if any (in enforce mode the responder normally exits first).
	 */
	public function handle( Request $request, ResponderInterface $responder, string $message ): ?Verdict {
		$verdict = $this->evaluate( $request );
		if ( null === $verdict ) {
			return null;
		}

		$reference = $this->record( $request, $verdict );

		if ( ! $this->monitor ) {
			$responder->deny( $verdict, $message, $reference );
		}
		return $verdict;
	}

	/**
	 * Write a log entry unless the same IP+rule was logged very recently.
	 *
	 * Without this, a flood from one IP would mean one database insert per
	 * request, which would do the attacker's work for them.
	 *
	 * @param Request $request Request.
	 * @param Verdict $verdict Verdict.
	 * @return int Log row id, or 0 if suppressed.
	 */
	private function record( Request $request, Verdict $verdict ): int {
		$key = 'log_seen:' . $verdict->rule() . ':' . $request->ip();
		if ( null !== $this->store->get( $key ) ) {
			return 0;
		}
		$this->store->set( $key, 1, self::LOG_DEDUPE_SECONDS );

		return $this->log->record(
			array(
				'ip'         => $request->ip(),
				'country'    => $this->geo ? (string) $this->geo->lookup( $request->ip() ) : '',
				'rule'       => $verdict->rule(),
				'action'     => $this->monitor ? BlockLogInterface::ACTION_MONITORED : BlockLogInterface::ACTION_BLOCKED,
				'reason'     => $verdict->reason(),
				'method'     => $request->method(),
				'uri'        => $request->uri(),
				'user_agent' => $request->user_agent(),
			)
		);
	}
}
