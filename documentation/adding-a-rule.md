# Adding a rule

A rule is a class implementing `WPBouncer\Rules\RuleInterface`:

```php
interface RuleInterface {
    public function id(): string;              // settings key and log label
    public function is_enabled(): bool;
    public function inspect( Request $request ): ?Verdict;   // null = let it in
}
```

Rules must get everything from the `Request` and from constructor arguments. **Don't read superglobals or call WordPress functions inside `inspect()`.** That restriction is what makes rules unit-testable.

## Option A: a new built-in rule

Example: refuse the TRACE, TRACK and CONNECT HTTP methods, which a WordPress site never needs.

**1. The rule**, `wp-bouncer/src/Rules/HttpMethodRule.php`:

```php
<?php
namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;

defined( 'ABSPATH' ) || exit;

/**
 * Refuses HTTP methods that a WordPress site never needs.
 *
 * Settings:
 * - enabled (bool)
 */
final class HttpMethodRule extends AbstractRule {

    public const ID = 'http_method';

    public function id(): string {
        return self::ID;
    }

    public function inspect( Request $request ): ?Verdict {
        if ( in_array( $request->method(), array( 'TRACE', 'TRACK', 'CONNECT' ), true ) ) {
            return $this->deny( 'HTTP method ' . $request->method() . ' is not allowed', 405 );
        }
        return null;
    }
}
```

**2. Settings**, in `wp-bouncer/src/Settings.php`:
- add `'http_method' => array( 'enabled' => true )` to `defaults()['rules']`
- add a block to `sanitize()` that copies and coerces each field
- add `'rules.http_method'` to `TAB_FIELDS['rules']`

**3. Wiring**, in `Plugin::build_rules()`: add `new HttpMethodRule( $s->rule( HttpMethodRule::ID ) )` at a position that suits its cost (this one is cheap, so near the top).

**4. UI**, in three places:

- `wp-bouncer/src/Admin/RuleCatalog.php`: add the id to `RuleCatalog::CATEGORIES`, in one of `block-lists`, `login-accounts`, `scanners-floods` or `payloads-hardening`. This is the only place a built-in rule declares its category. `RuleCatalogTest` fails if a rule in `Settings::defaults()` is missing here, or the reverse.
- `wp-bouncer/src/Admin/RuleLabels.php`: add its title and one-line description to `RuleLabels::rules()`. The Rules tab, the Dashboard and the log filter read the labels from there. (`AdminController::rule_labels()` delegates to it.)
- `wp-bouncer/src/Admin/views/rules/http_method.php`: the panel's inputs, with the same `wp_bouncer[rules][http_method][...]` names as the other panels and no heading (copy `views/rules/not_found.php` as a start). The Rules tab wraps it in a row with the switch, title and flags, and the row includes this file only for built-in ids. Don't disable the inputs, because a closed panel must still submit (see the round-trip contract in [architecture/rules-ui.md](architecture/rules-ui.md)).

**5. Tests**: add `tests/Unit/Rules/HttpMethodRuleTest.php` with cases that must be blocked and cases that must pass. `SettingsTest::test_defaults_survive_their_own_sanitisation` will fail if step 2 is incomplete, and `RuleCatalogTest` if step 4 is. The Rules tab round trip (`tests/Integration/Admin/RulesTabTest.php`) checks that saving the form unchanged changes no setting, so run it too.

**6. Docs**: add a section to [rules.md](rules.md).

## Option B: from another plugin

Use the `wp_bouncer_rules` filter. The rule shows up in the log under its `id()`.

```php
add_filter( 'wp_bouncer_rules', function ( array $rules ) {
    $rules[] = new class implements \WPBouncer\Rules\RuleInterface {
        public function id(): string { return 'no_wp_json_for_bots'; }
        public function is_enabled(): bool { return true; }
        public function inspect( \WPBouncer\Firewall\Request $r ): ?\WPBouncer\Firewall\Verdict {
            return ( '' !== $r->rest_route() && false !== stripos( $r->user_agent(), 'bot' ) )
                ? new \WPBouncer\Firewall\Verdict( $this->id(), 'Bot on REST API' )
                : null;
        }
    };
    return $rules;
} );
```

The filter runs on `plugins_loaded` priority 1, so register it from your plugin's main file, not from a later hook.

### Give the rule a category and a title (optional)

Without this, a third-party rule appears under **Other**, titled with its id. To place it in a category with a readable title, use the `wp_bouncer_rule_info` filter:

```php
add_filter( 'wp_bouncer_rule_info', function ( array $info ): array {
	$info['no_wp_json_for_bots'] = array(
		'category' => 'scanners-floods', // block-lists | login-accounts | scanners-floods | payloads-hardening | other
		'title'    => __( 'Bots on the REST API', 'my-plugin' ),
	);
	return $info;
} );
```

The filter's arguments are `$info` (an array, empty by default) and `$ids` (the ids of the non-built-in rules in the chain). Rules for the filter:

- It runs only when the Rules or Dashboard tab is built, never in the firewall path. Keep it cheap and free of side effects.
- A missing or unknown `category` goes to **Other**. The title is stripped of HTML and capped at 80 characters, and an empty title falls back to the id.
- An entry for an id that isn't in the rule chain is ignored, so the screen shows only rules that run.
- An entry for a built-in id is ignored, so built-in titles and categories can't be changed.
- The row shows the rule's state from `is_enabled()`, but no switch and no settings: the page says "Managed by the plugin that added it." If `id()` or `is_enabled()` throws, the row shows "Unknown" and the page still renders.
- A third-party row's anchor is `#rule-x-<id>` (the id passed through `sanitize_html_class`), so it can never clash with a built-in `#rule-<id>` anchor.

To read the same chain from your own code, call `Plugin::registered_rules()`. It returns the rule objects the firewall runs, built once per request, so it can be used from an admin screen or a test:

```php
$rules = \WPBouncer\Plugin::instance()->registered_rules(); // RuleInterface[]; instance() is null before the plugin has loaded
```

A rule that writes its own log rows should use `Plugin::log_writer()`, not `Plugin::log()`. The writer applies the site-wide write budget (see the [developer guide](developer-guide.md#hooks-filters-and-constants) for `wp_bouncer_log_budget_per_minute`), so a flood of matches can't fill the table. `log()` is for reads and the admin screens.

## Useful `Request` methods

`ip()`, `key_ip()` (the subject bans are keyed on), `method()`, `uri()`, `path()` (normalised, lowercase), `query()`, `post()`, `user_agent()`, `header( 'X-Name' )`, `body()` (lazy, 1 MB cap), `is_logged_in()` and `is_trusted()` (lazy), `is_login()`, `is_xmlrpc()`, `is_admin_area()`, `rest_route()`, `is_json()`, `could_be_json()`, `body_limited( $cap )`, `can_edit_posts()`, `can_be_banned()` (false for loopback and trusted proxies, and while the IP fallback suspends bans), `fetch_context()` (`cross-site`, `same-site`, `same-origin`, `none` or `unknown`), `is_foreign_fetch()` and `is_exempt_subresource()`.

## Verdict

`new Verdict( $rule_id, $reason, $status = 403, $retry_after = 0 )`. Inside an `AbstractRule` subclass, use `$this->deny( $reason, $status, $retry_after )`. The reason goes in the log, not to the visitor.
