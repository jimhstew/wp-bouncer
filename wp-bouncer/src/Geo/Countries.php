<?php
/**
 * ISO 3166-1 alpha-2 country list used by the country picker.
 *
 * @package WPBouncer
 */

namespace WPBouncer\Geo;

defined( 'ABSPATH' ) || exit;

/**
 * Country codes, names and continent groups.
 */
final class Countries {

	/**
	 * Pseudo-codes that some geo sources emit.
	 *
	 * T1 is set by Cloudflare's CF-IPCountry header for Tor exit nodes. EU and AP are used by
	 * some databases for addresses registered to a region rather than a country.
	 */
	public const SPECIAL = array(
		'T1' => 'Tor network (Cloudflare header only)',
		'EU' => 'Europe (region, unspecified country)',
		'AP' => 'Asia/Pacific (region, unspecified country)',
	);

	/**
	 * Code => [ name, continent ].
	 * Continents: AF Africa, AN Antarctica, AS Asia, EU Europe, NA North America, OC Oceania, SA South America.
	 */
	private const LIST = array(
		'AD' => array( 'Andorra', 'EU' ),
		'AE' => array( 'United Arab Emirates', 'AS' ),
		'AF' => array( 'Afghanistan', 'AS' ),
		'AG' => array( 'Antigua and Barbuda', 'NA' ),
		'AI' => array( 'Anguilla', 'NA' ),
		'AL' => array( 'Albania', 'EU' ),
		'AM' => array( 'Armenia', 'AS' ),
		'AO' => array( 'Angola', 'AF' ),
		'AQ' => array( 'Antarctica', 'AN' ),
		'AR' => array( 'Argentina', 'SA' ),
		'AS' => array( 'American Samoa', 'OC' ),
		'AT' => array( 'Austria', 'EU' ),
		'AU' => array( 'Australia', 'OC' ),
		'AW' => array( 'Aruba', 'NA' ),
		'AX' => array( 'Åland Islands', 'EU' ),
		'AZ' => array( 'Azerbaijan', 'AS' ),
		'BA' => array( 'Bosnia and Herzegovina', 'EU' ),
		'BB' => array( 'Barbados', 'NA' ),
		'BD' => array( 'Bangladesh', 'AS' ),
		'BE' => array( 'Belgium', 'EU' ),
		'BF' => array( 'Burkina Faso', 'AF' ),
		'BG' => array( 'Bulgaria', 'EU' ),
		'BH' => array( 'Bahrain', 'AS' ),
		'BI' => array( 'Burundi', 'AF' ),
		'BJ' => array( 'Benin', 'AF' ),
		'BL' => array( 'Saint Barthélemy', 'NA' ),
		'BM' => array( 'Bermuda', 'NA' ),
		'BN' => array( 'Brunei Darussalam', 'AS' ),
		'BO' => array( 'Bolivia', 'SA' ),
		'BQ' => array( 'Bonaire, Sint Eustatius and Saba', 'NA' ),
		'BR' => array( 'Brazil', 'SA' ),
		'BS' => array( 'Bahamas', 'NA' ),
		'BT' => array( 'Bhutan', 'AS' ),
		'BV' => array( 'Bouvet Island', 'AN' ),
		'BW' => array( 'Botswana', 'AF' ),
		'BY' => array( 'Belarus', 'EU' ),
		'BZ' => array( 'Belize', 'NA' ),
		'CA' => array( 'Canada', 'NA' ),
		'CC' => array( 'Cocos (Keeling) Islands', 'AS' ),
		'CD' => array( 'Congo, Democratic Republic of the', 'AF' ),
		'CF' => array( 'Central African Republic', 'AF' ),
		'CG' => array( 'Congo', 'AF' ),
		'CH' => array( 'Switzerland', 'EU' ),
		'CI' => array( "Côte d'Ivoire", 'AF' ),
		'CK' => array( 'Cook Islands', 'OC' ),
		'CL' => array( 'Chile', 'SA' ),
		'CM' => array( 'Cameroon', 'AF' ),
		'CN' => array( 'China', 'AS' ),
		'CO' => array( 'Colombia', 'SA' ),
		'CR' => array( 'Costa Rica', 'NA' ),
		'CU' => array( 'Cuba', 'NA' ),
		'CV' => array( 'Cabo Verde', 'AF' ),
		'CW' => array( 'Curaçao', 'NA' ),
		'CX' => array( 'Christmas Island', 'AS' ),
		'CY' => array( 'Cyprus', 'EU' ),
		'CZ' => array( 'Czechia', 'EU' ),
		'DE' => array( 'Germany', 'EU' ),
		'DJ' => array( 'Djibouti', 'AF' ),
		'DK' => array( 'Denmark', 'EU' ),
		'DM' => array( 'Dominica', 'NA' ),
		'DO' => array( 'Dominican Republic', 'NA' ),
		'DZ' => array( 'Algeria', 'AF' ),
		'EC' => array( 'Ecuador', 'SA' ),
		'EE' => array( 'Estonia', 'EU' ),
		'EG' => array( 'Egypt', 'AF' ),
		'EH' => array( 'Western Sahara', 'AF' ),
		'ER' => array( 'Eritrea', 'AF' ),
		'ES' => array( 'Spain', 'EU' ),
		'ET' => array( 'Ethiopia', 'AF' ),
		'FI' => array( 'Finland', 'EU' ),
		'FJ' => array( 'Fiji', 'OC' ),
		'FK' => array( 'Falkland Islands (Malvinas)', 'SA' ),
		'FM' => array( 'Micronesia', 'OC' ),
		'FO' => array( 'Faroe Islands', 'EU' ),
		'FR' => array( 'France', 'EU' ),
		'GA' => array( 'Gabon', 'AF' ),
		'GB' => array( 'United Kingdom', 'EU' ),
		'GD' => array( 'Grenada', 'NA' ),
		'GE' => array( 'Georgia', 'AS' ),
		'GF' => array( 'French Guiana', 'SA' ),
		'GG' => array( 'Guernsey', 'EU' ),
		'GH' => array( 'Ghana', 'AF' ),
		'GI' => array( 'Gibraltar', 'EU' ),
		'GL' => array( 'Greenland', 'NA' ),
		'GM' => array( 'Gambia', 'AF' ),
		'GN' => array( 'Guinea', 'AF' ),
		'GP' => array( 'Guadeloupe', 'NA' ),
		'GQ' => array( 'Equatorial Guinea', 'AF' ),
		'GR' => array( 'Greece', 'EU' ),
		'GS' => array( 'South Georgia and the South Sandwich Islands', 'AN' ),
		'GT' => array( 'Guatemala', 'NA' ),
		'GU' => array( 'Guam', 'OC' ),
		'GW' => array( 'Guinea-Bissau', 'AF' ),
		'GY' => array( 'Guyana', 'SA' ),
		'HK' => array( 'Hong Kong', 'AS' ),
		'HM' => array( 'Heard Island and McDonald Islands', 'AN' ),
		'HN' => array( 'Honduras', 'NA' ),
		'HR' => array( 'Croatia', 'EU' ),
		'HT' => array( 'Haiti', 'NA' ),
		'HU' => array( 'Hungary', 'EU' ),
		'ID' => array( 'Indonesia', 'AS' ),
		'IE' => array( 'Ireland', 'EU' ),
		'IL' => array( 'Israel', 'AS' ),
		'IM' => array( 'Isle of Man', 'EU' ),
		'IN' => array( 'India', 'AS' ),
		'IO' => array( 'British Indian Ocean Territory', 'AS' ),
		'IQ' => array( 'Iraq', 'AS' ),
		'IR' => array( 'Iran', 'AS' ),
		'IS' => array( 'Iceland', 'EU' ),
		'IT' => array( 'Italy', 'EU' ),
		'JE' => array( 'Jersey', 'EU' ),
		'JM' => array( 'Jamaica', 'NA' ),
		'JO' => array( 'Jordan', 'AS' ),
		'JP' => array( 'Japan', 'AS' ),
		'KE' => array( 'Kenya', 'AF' ),
		'KG' => array( 'Kyrgyzstan', 'AS' ),
		'KH' => array( 'Cambodia', 'AS' ),
		'KI' => array( 'Kiribati', 'OC' ),
		'KM' => array( 'Comoros', 'AF' ),
		'KN' => array( 'Saint Kitts and Nevis', 'NA' ),
		'KP' => array( 'North Korea', 'AS' ),
		'KR' => array( 'South Korea', 'AS' ),
		'KW' => array( 'Kuwait', 'AS' ),
		'KY' => array( 'Cayman Islands', 'NA' ),
		'KZ' => array( 'Kazakhstan', 'AS' ),
		'LA' => array( "Lao People's Democratic Republic", 'AS' ),
		'LB' => array( 'Lebanon', 'AS' ),
		'LC' => array( 'Saint Lucia', 'NA' ),
		'LI' => array( 'Liechtenstein', 'EU' ),
		'LK' => array( 'Sri Lanka', 'AS' ),
		'LR' => array( 'Liberia', 'AF' ),
		'LS' => array( 'Lesotho', 'AF' ),
		'LT' => array( 'Lithuania', 'EU' ),
		'LU' => array( 'Luxembourg', 'EU' ),
		'LV' => array( 'Latvia', 'EU' ),
		'LY' => array( 'Libya', 'AF' ),
		'MA' => array( 'Morocco', 'AF' ),
		'MC' => array( 'Monaco', 'EU' ),
		'MD' => array( 'Moldova', 'EU' ),
		'ME' => array( 'Montenegro', 'EU' ),
		'MF' => array( 'Saint Martin (French part)', 'NA' ),
		'MG' => array( 'Madagascar', 'AF' ),
		'MH' => array( 'Marshall Islands', 'OC' ),
		'MK' => array( 'North Macedonia', 'EU' ),
		'ML' => array( 'Mali', 'AF' ),
		'MM' => array( 'Myanmar', 'AS' ),
		'MN' => array( 'Mongolia', 'AS' ),
		'MO' => array( 'Macao', 'AS' ),
		'MP' => array( 'Northern Mariana Islands', 'OC' ),
		'MQ' => array( 'Martinique', 'NA' ),
		'MR' => array( 'Mauritania', 'AF' ),
		'MS' => array( 'Montserrat', 'NA' ),
		'MT' => array( 'Malta', 'EU' ),
		'MU' => array( 'Mauritius', 'AF' ),
		'MV' => array( 'Maldives', 'AS' ),
		'MW' => array( 'Malawi', 'AF' ),
		'MX' => array( 'Mexico', 'NA' ),
		'MY' => array( 'Malaysia', 'AS' ),
		'MZ' => array( 'Mozambique', 'AF' ),
		'NA' => array( 'Namibia', 'AF' ),
		'NC' => array( 'New Caledonia', 'OC' ),
		'NE' => array( 'Niger', 'AF' ),
		'NF' => array( 'Norfolk Island', 'OC' ),
		'NG' => array( 'Nigeria', 'AF' ),
		'NI' => array( 'Nicaragua', 'NA' ),
		'NL' => array( 'Netherlands', 'EU' ),
		'NO' => array( 'Norway', 'EU' ),
		'NP' => array( 'Nepal', 'AS' ),
		'NR' => array( 'Nauru', 'OC' ),
		'NU' => array( 'Niue', 'OC' ),
		'NZ' => array( 'New Zealand', 'OC' ),
		'OM' => array( 'Oman', 'AS' ),
		'PA' => array( 'Panama', 'NA' ),
		'PE' => array( 'Peru', 'SA' ),
		'PF' => array( 'French Polynesia', 'OC' ),
		'PG' => array( 'Papua New Guinea', 'OC' ),
		'PH' => array( 'Philippines', 'AS' ),
		'PK' => array( 'Pakistan', 'AS' ),
		'PL' => array( 'Poland', 'EU' ),
		'PM' => array( 'Saint Pierre and Miquelon', 'NA' ),
		'PN' => array( 'Pitcairn', 'OC' ),
		'PR' => array( 'Puerto Rico', 'NA' ),
		'PS' => array( 'Palestine, State of', 'AS' ),
		'PT' => array( 'Portugal', 'EU' ),
		'PW' => array( 'Palau', 'OC' ),
		'PY' => array( 'Paraguay', 'SA' ),
		'QA' => array( 'Qatar', 'AS' ),
		'RE' => array( 'Réunion', 'AF' ),
		'RO' => array( 'Romania', 'EU' ),
		'RS' => array( 'Serbia', 'EU' ),
		'RU' => array( 'Russian Federation', 'EU' ),
		'RW' => array( 'Rwanda', 'AF' ),
		'SA' => array( 'Saudi Arabia', 'AS' ),
		'SB' => array( 'Solomon Islands', 'OC' ),
		'SC' => array( 'Seychelles', 'AF' ),
		'SD' => array( 'Sudan', 'AF' ),
		'SE' => array( 'Sweden', 'EU' ),
		'SG' => array( 'Singapore', 'AS' ),
		'SH' => array( 'Saint Helena, Ascension and Tristan da Cunha', 'AF' ),
		'SI' => array( 'Slovenia', 'EU' ),
		'SJ' => array( 'Svalbard and Jan Mayen', 'EU' ),
		'SK' => array( 'Slovakia', 'EU' ),
		'SL' => array( 'Sierra Leone', 'AF' ),
		'SM' => array( 'San Marino', 'EU' ),
		'SN' => array( 'Senegal', 'AF' ),
		'SO' => array( 'Somalia', 'AF' ),
		'SR' => array( 'Suriname', 'SA' ),
		'SS' => array( 'South Sudan', 'AF' ),
		'ST' => array( 'Sao Tome and Principe', 'AF' ),
		'SV' => array( 'El Salvador', 'NA' ),
		'SX' => array( 'Sint Maarten (Dutch part)', 'NA' ),
		'SY' => array( 'Syrian Arab Republic', 'AS' ),
		'SZ' => array( 'Eswatini', 'AF' ),
		'TC' => array( 'Turks and Caicos Islands', 'NA' ),
		'TD' => array( 'Chad', 'AF' ),
		'TF' => array( 'French Southern Territories', 'AN' ),
		'TG' => array( 'Togo', 'AF' ),
		'TH' => array( 'Thailand', 'AS' ),
		'TJ' => array( 'Tajikistan', 'AS' ),
		'TK' => array( 'Tokelau', 'OC' ),
		'TL' => array( 'Timor-Leste', 'AS' ),
		'TM' => array( 'Turkmenistan', 'AS' ),
		'TN' => array( 'Tunisia', 'AF' ),
		'TO' => array( 'Tonga', 'OC' ),
		'TR' => array( 'Türkiye', 'AS' ),
		'TT' => array( 'Trinidad and Tobago', 'NA' ),
		'TV' => array( 'Tuvalu', 'OC' ),
		'TW' => array( 'Taiwan', 'AS' ),
		'TZ' => array( 'Tanzania', 'AF' ),
		'UA' => array( 'Ukraine', 'EU' ),
		'UG' => array( 'Uganda', 'AF' ),
		'UM' => array( 'United States Minor Outlying Islands', 'OC' ),
		'US' => array( 'United States', 'NA' ),
		'UY' => array( 'Uruguay', 'SA' ),
		'UZ' => array( 'Uzbekistan', 'AS' ),
		'VA' => array( 'Holy See (Vatican City)', 'EU' ),
		'VC' => array( 'Saint Vincent and the Grenadines', 'NA' ),
		'VE' => array( 'Venezuela', 'SA' ),
		'VG' => array( 'Virgin Islands (British)', 'NA' ),
		'VI' => array( 'Virgin Islands (U.S.)', 'NA' ),
		'VN' => array( 'Viet Nam', 'AS' ),
		'VU' => array( 'Vanuatu', 'OC' ),
		'WF' => array( 'Wallis and Futuna', 'OC' ),
		'WS' => array( 'Samoa', 'OC' ),
		'YE' => array( 'Yemen', 'AS' ),
		'YT' => array( 'Mayotte', 'AF' ),
		'ZA' => array( 'South Africa', 'AF' ),
		'ZM' => array( 'Zambia', 'AF' ),
		'ZW' => array( 'Zimbabwe', 'AF' ),
	);

	/** Continent code => display name. */
	public const CONTINENTS = array(
		'AF' => 'Africa',
		'AN' => 'Antarctica',
		'AS' => 'Asia',
		'EU' => 'Europe',
		'NA' => 'North America',
		'OC' => 'Oceania',
		'SA' => 'South America',
	);

	/**
	 * All selectable codes => names (countries, then special codes).
	 *
	 * @return array<string, string>
	 */
	public static function all(): array {
		$out = array();
		foreach ( self::LIST as $code => $info ) {
			$out[ $code ] = $info[0];
		}
		return $out + self::SPECIAL;
	}

	/**
	 * Continent of a country code ('' for special codes).
	 *
	 * @param string $code Country code.
	 */
	public static function continent( string $code ): string {
		return self::LIST[ $code ][1] ?? '';
	}

	/**
	 * Display name for a code (falls back to the code itself).
	 *
	 * @param string $code Country code.
	 */
	public static function name( string $code ): string {
		$all = self::all();
		return $all[ $code ] ?? $code;
	}

	/**
	 * Is the code selectable?
	 *
	 * @param string $code Country code.
	 */
	public static function is_valid( string $code ): bool {
		return isset( self::LIST[ $code ] ) || isset( self::SPECIAL[ $code ] );
	}
}
