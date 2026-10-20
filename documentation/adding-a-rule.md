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

Example: block requests for backup and dump files (`.sql`, `.bak`, `.zip` in wp-content).

**1. The rule**, `wp-bouncer/src/Rules/BackupProbeRule.php`:

```php
<?php
namespace WPBouncer\Rules;

use WPBouncer\Firewall\Request;
use WPBouncer\Firewall\Verdict;

defined( 'ABSPATH' ) || exit;

/**
 * Refuses probes for leftover backup files.
 *
 * Settings:
 * - enabled (bool)
 */
final class BackupProbeRule extends AbstractRule {

    public const ID = 'backup_probe';

    public function id(): string {
        return self::ID;
    }

    public function inspect( Request $request ): ?Verdict {
        if ( preg_match( '#\.(sql|bak|old|tar\.gz|zip)$#', $request->path() ) ) {
            return $this->deny( 'Backup file probe' );
        }
        return null;
    }
}
```

**2. Settings**, in `wp-bouncer/src/Settings.php`:
- add `'backup_probe' => array( 'enabled' => true )` to `defaults()['rules']`
- add a block to `sanitize()` that copies and coerces each field
- add `'rules.backup_probe'` to `TAB_FIELDS['rules']`

**3. Wiring**, in `Plugin::build_rules()`: add `new BackupProbeRule( $s->rule( BackupProbeRule::ID ) )` at a position that suits its cost.

**4. UI**: add a label to `AdminController::rule_labels()` (this also adds it to the Dashboard and the log filter), and add a panel to `wp-bouncer/src/Admin/views/rules.php` using `$heading( 'backup_probe' )`.

**5. Tests**: add `tests/Unit/Rules/BackupProbeRuleTest.php` with cases that must be blocked and cases that must pass. `SettingsTest::test_defaults_survive_their_own_sanitisation` will fail if step 2 is incomplete.

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

## Useful `Request` methods

`ip()`, `method()`, `uri()`, `path()` (normalised, lowercase), `query()`, `post()`, `user_agent()`, `header( 'X-Name' )`, `body()` (lazy, 1 MB cap), `is_logged_in()` and `is_trusted()` (lazy), `is_login()`, `is_xmlrpc()`, `is_admin_area()`, `rest_route()`.

## Verdict

`new Verdict( $rule_id, $reason, $status = 403, $retry_after = 0 )`. Inside an `AbstractRule` subclass, use `$this->deny( $reason, $status, $retry_after )`. The reason goes in the log, not to the visitor.
