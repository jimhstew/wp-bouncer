<?php
/**
 * CI self-check for the supply chain of the build itself (RT-02, SB-08, SB-25).
 *
 *   php scripts/ci-selfcheck.php [repo-root]
 *
 * Exits 1 and lists every problem when:
 *   - a `uses:` in a workflow is not pinned to a 40-character commit SHA (a trailing
 *     "# version" comment is also required, so humans and Dependabot can read the pin);
 *   - a workflow has no top-level `permissions:`, or a job has no `permissions:` of its own;
 *   - a job holds a write permission but has a step other than downloading an artifact and
 *     running `gh release`, or checks out the repository;
 *   - the wp-cli or SQLite plugin downloads in tests/e2e/run.sh lose their pinned checksum,
 *     or the old "latest" download URLs come back;
 *   - wp-phpunit is unbounded in composer.json, or .github/dependabot.yml is missing.
 *
 * It reads the workflow files line by line (no YAML extension needed), which is enough for the
 * plain layout these workflows use: jobs at two spaces, job keys at four, steps at six.
 *
 * Plain PHP, no WordPress and no Composer packages, so it runs before anything is installed.
 */

$root   = rtrim( $argv[1] ?? dirname( __DIR__ ), '/' );
$errors = array();

$files = glob( $root . '/.github/workflows/*.{yml,yaml}', GLOB_BRACE );
if ( empty( $files ) ) {
	$errors[] = 'no workflow files found in .github/workflows';
}

foreach ( (array) $files as $file ) {
	$name  = '.github/workflows/' . basename( $file );
	$lines = file( $file, FILE_IGNORE_NEW_LINES );

	$top_permissions = false;
	$jobs            = array(); // job id => list of [line number, text].
	$current         = null;
	$in_jobs         = false;

	foreach ( $lines as $i => $line ) {
		$no = $i + 1;
		if ( preg_match( '/^\s*#/', $line ) ) {
			continue;
		}
		if ( preg_match( '/^permissions:/', $line ) ) {
			$top_permissions = true;
		}
		if ( preg_match( '/^jobs:\s*$/', $line ) ) {
			$in_jobs = true;
			continue;
		}
		if ( $in_jobs && preg_match( '/^[A-Za-z_-]+:/', $line ) ) {
			$in_jobs = false;
			$current = null;
		}
		if ( $in_jobs && preg_match( '/^  ([A-Za-z0-9_-]+):\s*$/', $line, $m ) ) {
			$current          = $m[1];
			$jobs[ $current ] = array();
			continue;
		}
		if ( null !== $current ) {
			$jobs[ $current ][] = array( $no, $line );
		}

		// Every uses: must be a local action or a full SHA with a version comment.
		if ( preg_match( '/^\s*-?\s*uses:\s*(\S+)(.*)$/', $line, $m ) ) {
			$ref = $m[1];
			if ( 0 === strpos( $ref, './' ) ) {
				continue;
			}
			if ( ! preg_match( '/^[\w.-]+\/[\w.\/-]+@[0-9a-f]{40}$/', $ref ) ) {
				$errors[] = "$name:$no: '$ref' is not pinned to a 40-character commit SHA";
			} elseif ( ! preg_match( '/^\s+#\s*\S+/', $m[2] ) ) {
				$errors[] = "$name:$no: '$ref' needs a trailing '# <version>' comment";
			}
		}
	}

	foreach ( $lines as $i => $line ) {
		if ( preg_match( '/^\s*pull_request_target\b/', $line ) || preg_match( '/^on:.*pull_request_target/', $line ) ) {
			$errors[] = "$name:" . ( $i + 1 ) . ': pull_request_target is not allowed';
		}
	}
	$in_top = false;
	foreach ( $lines as $i => $line ) {
		if ( preg_match( '/^permissions:\s*(.*)$/', $line, $m ) ) {
			$in_top = true;
			if ( preg_match( '/write/', $m[1] ) ) {
				$errors[] = "$name:" . ( $i + 1 ) . ': top-level permissions must not grant write';
			}
		} elseif ( $in_top && preg_match( '/^  \S.*write/', $line ) ) {
			$errors[] = "$name:" . ( $i + 1 ) . ': top-level permissions must not grant write';
		} elseif ( $in_top && preg_match( '/^\S/', $line ) ) {
			$in_top = false;
		}
	}

	if ( ! $top_permissions ) {
		$errors[] = "$name: no top-level 'permissions:' (use 'permissions: {}' or 'contents: read')";
	}

	foreach ( $jobs as $id => $body ) {
		$text = implode( "\n", array_column( $body, 1 ) );
		if ( ! preg_match( '/^    permissions:/m', $text ) ) {
			$errors[] = "$name: job '$id' has no 'permissions:' of its own";
			continue;
		}

		// The job's permissions block: the lines indented deeper than "    permissions:".
		$perms = array();
		$grab  = false;
		foreach ( $body as $entry ) {
			$line = $entry[1];
			if ( preg_match( '/^    permissions:\s*(.*)$/', $line, $m ) ) {
				$grab = true;
				if ( '' !== trim( $m[1] ) ) {
					$perms[] = $m[1]; // Inline form, e.g. "permissions: write-all".
				}
				continue;
			}
			if ( $grab && preg_match( '/^      \S/', $line ) ) {
				$perms[] = trim( $line );
			} elseif ( $grab && '' !== trim( $line ) ) {
				$grab = false;
			}
		}
		$perm_text = implode( "\n", $perms );
		if ( preg_match( '/write-all/', $perm_text ) ) {
			$errors[] = "$name: job '$id' uses write-all";
		}
		if ( ! preg_match( '/\bwrite\b/', $perm_text ) ) {
			continue;
		}

		// A job that can write: no checkout, only artifact download and `gh release`.
		foreach ( $body as $entry ) {
			if ( preg_match( '/uses:\s*(\S+)@/', $entry[1], $m ) && 'actions/download-artifact' !== $m[1] ) {
				$errors[] = "$name:{$entry[0]}: job '$id' can write but uses '{$m[1]}' (only actions/download-artifact is allowed)";
			}
		}
		if ( preg_match_all( '/^\s*-?\s*run:\s*(.*)$/m', $text, $runs, PREG_SET_ORDER ) ) {
			foreach ( $body as $k => $entry ) {
				if ( ! preg_match( '/^(\s*)-?\s*run:\s*(.*)$/', $entry[1], $m ) ) {
					continue;
				}
				// Collect the run body: the rest of this line plus deeper-indented lines.
				$indent = strlen( $m[1] );
				$script = $m[2];
				for ( $j = $k + 1; $j < count( $body ); $j++ ) {
					$next = $body[ $j ][1];
					if ( '' !== trim( $next ) && strlen( $next ) - strlen( ltrim( $next ) ) <= $indent + 1 && preg_match( '/^\s*-\s|^\s*[a-z-]+:/', $next ) ) {
						break;
					}
					$script .= "\n" . $next;
				}
				if ( false === strpos( $script, 'gh release' ) ) {
					$errors[] = "$name:{$entry[0]}: job '$id' can write but has a run step that is not 'gh release'";
				}
				if ( preg_match( '/\b(composer|make|npm|pip|php|curl|wget)\b/', preg_replace( '/^\s*#.*$/m', '', $script ) ) ) {
					$errors[] = "$name:{$entry[0]}: job '$id' can write and runs build or download tooling";
				}
			}
		}
	}
}

// Downloaded tools are pinned and verified.
$run = @file_get_contents( $root . '/tests/e2e/run.sh' );
if ( false === $run ) {
	$errors[] = 'tests/e2e/run.sh not found';
} else {
	if ( ! preg_match( '/^WPCLI_VERSION="\d+\.\d+\.\d+"/m', $run ) || ! preg_match( '/^WPCLI_SHA512="[0-9a-f]{128}"/m', $run ) ) {
		$errors[] = 'tests/e2e/run.sh: wp-cli needs WPCLI_VERSION and a 128-hex WPCLI_SHA512';
	}
	if ( ! preg_match( '/^SQLITE_PLUGIN_VERSION="\d+\.\d+(\.\d+)?"/m', $run ) || ! preg_match( '/^SQLITE_PLUGIN_SHA256="[0-9a-f]{64}"/m', $run ) ) {
		$errors[] = 'tests/e2e/run.sh: the SQLite plugin needs SQLITE_PLUGIN_VERSION and a 64-hex SQLITE_PLUGIN_SHA256';
	}
	if ( false !== strpos( $run, 'gh-pages/phar' ) || false !== strpos( $run, 'latest-stable' ) ) {
		$errors[] = 'tests/e2e/run.sh: unpinned download URL (gh-pages/phar or latest-stable)';
	}
}

$composer = json_decode( (string) @file_get_contents( $root . '/composer.json' ), true );
if ( ! is_array( $composer ) ) {
	$errors[] = 'composer.json is missing or invalid';
} else {
	foreach ( $composer['require-dev'] ?? array() as $pkg => $range ) {
		if ( '*' === trim( $range ) ) {
			$errors[] = "composer.json: '$pkg' has the unbounded range '*'";
		}
	}
	if ( empty( $composer['config']['allow-plugins'] ) ) {
		$errors[] = 'composer.json: config.allow-plugins must list the allowed Composer plugins explicitly';
	}
}

if ( ! is_file( $root . '/.github/dependabot.yml' ) ) {
	$errors[] = '.github/dependabot.yml is missing';
}

if ( $errors ) {
	fwrite( STDERR, "CI self-check failed:\n  - " . implode( "\n  - ", $errors ) . "\n" );
	exit( 1 );
}
echo 'CI self-check OK (' . count( $files ) . " workflow files)\n";
