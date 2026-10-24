/**
 * WP Bouncer admin behaviour: deep links that open a rule's settings, the Rules
 * tab's unsaved-change text and expand/collapse buttons, country picker
 * filtering and selection, the "Add my IP" button, and driving the geo database
 * import step by step. Plain JS, no dependencies.
 *
 * Everything on the Rules tab works without this file: the settings sit in
 * native <details> panels and every input is submitted whether the panel is
 * open or not. This only adds comfort.
 */
( function () {
	'use strict';

	var cfg = window.wpBouncer || { yourIp: '', i18n: { selected: '%d selected' } };

	function $all( selector, root ) {
		return Array.prototype.slice.call( ( root || document ).querySelectorAll( selector ) );
	}

	var i18n = cfg.i18n || {};

	/* Deep links ---------------------------------------------------------- */

	// Open the target's collapsed panels, scroll to it and move focus there. The id comes from
	// the URL, so it is only ever passed to getElementById() (never used as a selector) and
	// only acted on inside our own screen.
	var root = document.querySelector( '.wp-bouncer' );

	var reveal = function ( hash ) {
		var id;
		try {
			id = decodeURIComponent( String( hash || '' ).replace( /^#/, '' ) );
		} catch ( e ) {
			return;
		}
		var el = id ? document.getElementById( id ) : null;
		if ( ! root || ! el || ! root.contains( el ) ) {
			return;
		}
		var node = el.parentNode;
		while ( node && node !== root ) {
			if ( node.tagName === 'DETAILS' ) {
				node.open = true;
			}
			node = node.parentNode;
		}
		if ( el.classList.contains( 'wpb-rule' ) ) {
			var own = el.querySelector( '.wpb-rule-settings' );
			if ( own ) {
				own.open = true;
			}
		}
		if ( ! el.hasAttribute( 'tabindex' ) ) {
			el.setAttribute( 'tabindex', '-1' );
		}
		el.scrollIntoView( { block: 'start' } );
		el.focus( { preventScroll: true } );
	};

	if ( root ) {
		window.addEventListener( 'hashchange', function () {
			reveal( window.location.hash );
		} );
		// Clicking the link for the hash we are already on fires no hashchange.
		root.addEventListener( 'click', function ( e ) {
			var link = e.target.closest ? e.target.closest( 'a[href^="#"]' ) : null;
			if ( link && link.getAttribute( 'href' ) === window.location.hash ) {
				reveal( window.location.hash );
			}
		} );
		// A value the browser refuses (out of range) inside a closed panel can't be focused,
		// so the submit would seem to do nothing: open the panel first.
		document.addEventListener( 'invalid', function ( e ) {
			var field = e.target;
			if ( ! field.closest || ! field.closest( '.wp-bouncer form' ) ) {
				return;
			}
			var panel = field.closest( 'details' );
			while ( panel ) {
				panel.open = true;
				panel = panel.parentNode && panel.parentNode.closest ? panel.parentNode.closest( 'details' ) : null;
			}
		}, true );
	}

	/* Rules tab ------------------------------------------------------------ */

	var rulesForm = document.querySelector( 'form.wpb-rules-form' );
	var OPEN_KEY = 'wpbRulesOpen';
	// The remembered panels are for the page right after a Rules-tab save only: any other
	// WP Bouncer page forgets them, so they cannot resurface on a later visit.
	if ( root && ! rulesForm ) {
		try {
			window.sessionStorage.removeItem( OPEN_KEY );
		} catch ( e ) {
			// Storage can be disabled.
		}
	}
	if ( rulesForm ) {
		var panels = function () {
			return $all( '.wpb-rule-settings', rulesForm );
		};

		// Reopen the panels that were open before the last save.
		try {
			var stored = JSON.parse( window.sessionStorage.getItem( OPEN_KEY ) || '[]' );
			window.sessionStorage.removeItem( OPEN_KEY );
			if ( Array.isArray( stored ) ) {
				stored.forEach( function ( id ) {
					var row = typeof id === 'string' ? document.getElementById( id ) : null;
					var panel = row && rulesForm.contains( row ) && row.classList.contains( 'wpb-rule' ) ? row.querySelector( '.wpb-rule-settings' ) : null;
					if ( panel ) {
						panel.open = true;
					}
				} );
			}
		} catch ( e ) {
			// Storage can be disabled. Nothing is lost: the panels just start closed.
		}

		rulesForm.addEventListener( 'submit', function () {
			try {
				var open = panels().filter( function ( p ) { return p.open; } ).map( function ( p ) { return p.parentNode.id; } );
				window.sessionStorage.setItem( OPEN_KEY, JSON.stringify( open ) );
			} catch ( e ) {
				// Ignore: see above.
			}
		} );

		// Say which switches changed but are not saved yet. textContent only.
		var unsaved = rulesForm.querySelector( '.wpb-unsaved' );
		var announced = false;
		rulesForm.addEventListener( 'change', function ( e ) {
			var input = e.target;
			if ( input.matches && input.matches( '.wpb-switch input' ) ) {
				var row = input.closest( '.wpb-rule' );
				var state = row ? row.querySelector( '.wpb-state' ) : null;
				// No data-saved means the state is not a plain On/Off (removed or unknown): leave the text alone.
				if ( state && state.hasAttribute( 'data-saved' ) && i18n.on && i18n.off && i18n.notSaved ) {
					var now = input.checked ? 'on' : 'off';
					state.textContent = ( input.checked ? i18n.on : i18n.off ) + ( now !== state.getAttribute( 'data-saved' ) ? ' ' + i18n.notSaved : '' );
				}
			}
			if ( unsaved && ! announced ) {
				announced = true;
				unsaved.textContent = i18n.unsaved || '';
			}
		} );

		// Expand all / Collapse all (rendered hidden: they do nothing without this script).
		var bar = document.querySelector( '.wpb-expand' );
		// Without both labels the buttons would be blank: leave them hidden.
		if ( bar && i18n.expandAll && i18n.collapseAll ) {
			$all( '[data-wpb-expand]', bar ).forEach( function ( btn ) {
				var all = btn.getAttribute( 'data-wpb-expand' ) === 'all';
				btn.textContent = all ? i18n.expandAll : i18n.collapseAll;
				btn.addEventListener( 'click', function () {
					panels().forEach( function ( p ) { p.open = all; } );
				} );
			} );
			bar.hidden = false;
		}
	}

	if ( root && window.location.hash ) {
		reveal( window.location.hash );
	}

	/* Country picker ------------------------------------------------------ */

	var form = document.getElementById( 'wpb-countries-form' );
	if ( form ) {
		var filter = document.getElementById( 'wpb-country-filter' );
		var counter = form.querySelector( '.wpb-country-count' );
		var boxes = $all( '.wpb-country input[type=checkbox]', form );

		var updateCount = function () {
			var n = boxes.filter( function ( b ) { return b.checked; } ).length;
			if ( counter ) {
				counter.textContent = cfg.i18n.selected.replace( '%d', n );
			}
		};

		var applyFilter = function () {
			var q = ( filter.value || '' ).trim().toLowerCase();
			$all( '.wpb-country', form ).forEach( function ( label ) {
				var match = ! q || label.getAttribute( 'data-name' ).indexOf( q ) !== -1;
				label.classList.toggle( 'is-hidden', ! match );
			} );
			$all( '.wpb-continent', form ).forEach( function ( fs ) {
				fs.hidden = $all( '.wpb-country:not(.is-hidden)', fs ).length === 0;
			} );
		};

		if ( filter ) {
			filter.addEventListener( 'input', applyFilter );
			// Enter in the filter box shouldn't submit the form.
			filter.addEventListener( 'keydown', function ( e ) {
				if ( e.key === 'Enter' ) {
					e.preventDefault();
				}
			} );
		}

		form.addEventListener( 'change', updateCount );

		form.addEventListener( 'click', function ( e ) {
			var btn = e.target.closest( 'button' );
			if ( ! btn ) {
				return;
			}
			if ( btn.hasAttribute( 'data-wpb-select' ) ) {
				var mode = btn.getAttribute( 'data-wpb-select' );
				boxes.forEach( function ( b ) {
					if ( mode === 'none' ) {
						b.checked = false;
					} else if ( ! b.closest( '.wpb-country' ).classList.contains( 'is-hidden' ) ) {
						b.checked = true;
					}
				} );
				updateCount();
			} else if ( btn.hasAttribute( 'data-wpb-continent' ) ) {
				var group = $all( '.wpb-country:not(.is-hidden) input', btn.closest( '.wpb-continent' ) );
				var allOn = group.every( function ( b ) { return b.checked; } );
				group.forEach( function ( b ) { b.checked = ! allOn; } );
				updateCount();
			}
		} );

		updateCount();
	}

	/* "Add my IP" --------------------------------------------------------- */

	$all( '[data-wpb-add-ip]' ).forEach( function ( btn ) {
		btn.addEventListener( 'click', function () {
			var target = document.querySelector( btn.getAttribute( 'data-wpb-add-ip' ) );
			if ( ! target || ! cfg.yourIp ) {
				return;
			}
			var lines = target.value.split( /\r?\n/ ).map( function ( l ) { return l.trim(); } ).filter( Boolean );
			if ( lines.indexOf( cfg.yourIp ) === -1 ) {
				lines.push( cfg.yourIp );
			}
			target.value = lines.join( '\n' );
			target.focus();
		} );
	} );

	/* Geo import ---------------------------------------------------------- */

	// The server imports a few seconds' worth of rows per request. Keep asking
	// until it says done. A step that fails outright (timeout, 500, network)
	// is retried a few times, which is safe because re-inserting rows is a no-op.
	var progress = document.getElementById( 'wpb-geo-progress' );
	if ( progress && cfg.ajaxUrl && window.fetch && window.FormData ) {
		var bar = progress.querySelector( 'progress' );
		var status = progress.querySelector( '.wpb-geo-status' );
		var continueForm = progress.querySelector( '.wpb-geo-continue' );
		var failures = 0;
		var maxFailures = 3;

		if ( continueForm ) {
			continueForm.hidden = true;
		}

		var showError = function ( message ) {
			progress.classList.add( 'is-error' );
			status.textContent = '';
			var strong = document.createElement( 'span' );
			strong.className = 'wpb-geo-error';
			strong.textContent = cfg.i18n.geoFailed + ' ' + message + ' ';
			var retry = document.createElement( 'button' );
			retry.type = 'button';
			retry.className = 'button';
			retry.textContent = cfg.i18n.geoRetry;
			retry.addEventListener( 'click', function () {
				progress.classList.remove( 'is-error' );
				failures = 0;
				step();
			} );
			status.appendChild( strong );
			status.appendChild( retry );
		};

		var step = function () {
			var body = new FormData();
			body.append( 'action', 'wp_bouncer_geo_step' );
			body.append( '_ajax_nonce', cfg.geoNonce );

			fetch( cfg.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' } )
				.then( function ( response ) {
					return response.json().catch( function () {
						throw new Error( 'HTTP ' + response.status );
					} );
				} )
				.then( function ( json ) {
					if ( ! json || ! json.success ) {
						// The server answered with a reason; retrying won't help.
						failures = maxFailures;
						throw new Error( ( json && json.data && json.data.message ) || 'Unknown error' );
					}
					failures = 0;
					var d = json.data;
					bar.value = d.percent;
					status.textContent = cfg.i18n.geoProgress
						.replace( '%1$s', d.percent )
						.replace( '%%', '%' )
						.replace( '%2$s', Number( d.imported ).toLocaleString() );
					if ( d.done ) {
						window.location.href = cfg.toolsUrl + '&wpb_msg=geo_done&wpb_n=' + encodeURIComponent( d.imported || 0 ) + '&wpb_skipped=' + encodeURIComponent( d.skipped || 0 );
					} else {
						step();
					}
				} )
				.catch( function ( err ) {
					failures++;
					if ( failures < maxFailures ) {
						window.setTimeout( step, 2000 );
					} else {
						showError( err.message );
					}
				} );
		};

		step();
	}
} )();
