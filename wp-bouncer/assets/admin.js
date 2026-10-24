/**
 * WP Bouncer admin behaviour: country picker filtering and selection, the
 * "Add my IP" button, and driving the geo database import step by step.
 * Plain JS, no dependencies.
 */
( function () {
	'use strict';

	var cfg = window.wpBouncer || { yourIp: '', i18n: { selected: '%d selected' } };

	function $all( selector, root ) {
		return Array.prototype.slice.call( ( root || document ).querySelectorAll( selector ) );
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
