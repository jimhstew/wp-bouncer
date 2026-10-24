<?php
/**
 * The bouncer: runs the rules and acts on the first objection.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Firewall;

use WPBouncer\Geo\GeoProviderInterface;
use WPBouncer\Log\BlockLogInterface;
use WPBouncer\Log\WriteBudget;
use WPBouncer\Rules\RuleInterface;
use WPBouncer\Storage\CounterStoreInterface;
use WPBouncer\Support\CounterSubject;
use WPBouncer\Support\IpUtils;

defined( 'ABSPATH' ) || exit;

/**
 * Request flow:
 *
 *   1. Exempt? Allowlisted IPs and requests from the server itself (loopback with no
 *      forwarding header: WP-Cron, health checks) pass.
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

	/**
	 * Rules in evaluation order.
	 *
	 * @var RuleInterface[]
	 */
	private array $rules;
	/**
	 * IPs and CIDRs that bypass every rule.
	 *
	 * @var string[]
	 */
	private array $allowlist;
	/**
	 * Whether the firewall only logs.
	 *
	 * @var bool
	 */
	private bool $monitor;
	/**
	 * Block log.
	 *
	 * @var BlockLogInterface
	 */
	private BlockLogInterface $log;
	/**
	 * Counter store.
	 *
	 * @var CounterStoreInterface
	 */
	private CounterStoreInterface $store;
	/**
	 * Country lookup.
	 *
	 * @var GeoProviderInterface|null
	 */
	private ?GeoProviderInterface $geo;
	/**
	 * Log write budget.
	 *
	 * @var WriteBudget|null
	 */
	private ?WriteBudget $budget;

	/**
	 * Set up the Firewall.
	 *
	 * @param RuleInterface[]           $rules     Rules in evaluation order.
	 * @param string[]                  $allowlist IPs / CIDRs that bypass every rule.
	 * @param bool                      $monitor   True for log-only mode.
	 * @param BlockLogInterface         $log       Block log.
	 * @param CounterStoreInterface     $store     Used for log de-duplication.
	 * @param GeoProviderInterface|null $geo       Adds the country to log entries.
	 * @param WriteBudget|null          $budget    Per-minute log write budget.
	 */
	public function __construct( array $rules, array $allowlist, bool $monitor, BlockLogInterface $log, CounterStoreInterface $store, ?GeoProviderInterface $geo = null, ?WriteBudget $budget = null ) {
		$this->rules     = $rules;
		$this->allowlist = $allowlist;
		$this->monitor   = $monitor;
		$this->log       = $log;
		$this->store     = $store;
		$this->geo       = $geo;
		$this->budget    = $budget;
	}

	/**
	 * Should this request skip every rule?
	 *
	 * @param Request $request Request.
	 */
	public function is_exempt( Request $request ): bool {
		if ( $request->is_local() ) {
			return true;
		}
		$ip = $request->ip();
		return '' !== $ip && IpUtils::matches_any( $ip, $this->allowlist );
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
	 * Key that suppresses repeat log rows: per rule and counter subject (an IPv6 network, not one address).
	 *
	 * @param string $rule Rule id.
	 * @param string $ip   Client IP.
	 */
	public static function dedupe_key( string $rule, string $ip ): string {
		return 'log_seen:' . $rule . ':' . CounterSubject::key( $ip );
	}

	/**
	 * Every de-dup and dropped-marker key for an address, to clear on unlock.
	 *
	 * @param string   $ip    Client IP as typed.
	 * @param string[] $rules Rule ids.
	 * @return string[]
	 */
	public static function log_keys( string $ip, array $rules ): array {
		$keys = array();
		foreach ( $rules as $rule ) {
			foreach ( CounterSubject::keys( $ip ) as $part ) {
				$keys[] = 'log_seen:' . $rule . ':' . $part;
				$keys[] = 'log_dropped:' . $rule . ':' . $part;
			}
		}
		return $keys;
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
		$key = self::dedupe_key( $verdict->rule(), $request->ip() );
		if ( null !== $this->store->get( $key ) ) {
			return 0;
		}
		// Over budget: no row and no de-dup key, so a flood of distinct IPs writes nothing.
		// A short marker (capped per minute) stops one IP's repeats being counted again.
		$action = $this->monitor ? BlockLogInterface::ACTION_MONITORED : BlockLogInterface::ACTION_BLOCKED;
		if ( $this->budget ) {
			$marker = 'log_dropped:' . $verdict->rule() . ':' . CounterSubject::key( $request->ip() );
			if ( null !== $this->store->get( $marker ) ) {
				return 0;
			}
			$priority = WriteBudget::is_priority(
				array(
					'rule'   => $verdict->rule(),
					'action' => $action,
				)
			);
			if ( ! $this->budget->peek( $verdict->rule(), $priority ) ) {
				if ( $this->budget->allow_marker() ) {
					$this->store->set( $marker, 1, self::LOG_DEDUPE_SECONDS );
				}
				return 0;
			}
		}
		$this->store->set( $key, 1, self::LOG_DEDUPE_SECONDS );

		return $this->log->record(
			array(
				'ip'         => $request->ip(),
				'country'    => $this->geo ? (string) $this->geo->lookup( $request->ip() ) : '',
				'rule'       => $verdict->rule(),
				'action'     => $action,
				'reason'     => $verdict->reason(),
				'method'     => $request->method(),
				'uri'        => $request->uri(),
				'user_agent' => $request->user_agent(),
			)
		);
	}
}
