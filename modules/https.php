<?php
/**
 * Modul: Tving HTTPS (2.5.0)
 * – 301 fra http til https, men bare når pluginens egen selvsjekk av
 *   sertifikatet har lykkes og WordPress sin adresse er https.
 * – Strict-Transport-Security på sikre svar når tvangen er aktiv.
 * – Selvsjekken kjøres i bakgrunnen (wp-cron) én gang i døgnet, og rett
 *   etter aktivering og oppgradering. Ingen besøkende venter på den.
 *   Lagres innstillingene i wp-admin, kjøres den med en gang.
 *   Ingen side kan låse seg selv ute.
 */

defined( 'ABSPATH' ) || exit;

add_action( 'init',         'ikss_https_redirect', 3 );
add_action( 'send_headers', 'ikss_https_hsts_header' );
add_action( 'update_option_ikss_force_https', 'ikss_https_selfcheck' );
add_action( 'admin_notices', 'ikss_https_admin_notice' );
add_action( 'ikss_https_selfcheck_event', 'ikss_https_selfcheck' );

/** Daglig bakgrunnsjobb. Kalles ved aktivering og oppgradering. */
function ikss_https_schedule() {
    if ( ! wp_next_scheduled( 'ikss_https_selfcheck_event' ) ) {
        wp_schedule_event( time() + 60, 'daily', 'ikss_https_selfcheck_event' );
    }
}

function ikss_https_unschedule() {
    $neste = wp_next_scheduled( 'ikss_https_selfcheck_event' );
    while ( $neste ) {
        wp_unschedule_event( $neste, 'ikss_https_selfcheck_event' );
        $neste = wp_next_scheduled( 'ikss_https_selfcheck_event' );
    }
}

/** Kjør selvsjekken i bakgrunnen så snart som mulig (ikke i besøkendes forespørsel). */
function ikss_https_selfcheck_soon() {
    if ( ! wp_next_scheduled( 'ikss_https_selfcheck_event' ) ) {
        ikss_https_schedule();
    }
    wp_schedule_single_event( time() + 5, 'ikss_https_selfcheck_event' );
}

/** Er forespørselen sikret, også bak proxy? */
function ikss_request_is_https() {
    if ( is_ssl() ) return true;
    if ( ! empty( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && strtolower( (string) $_SERVER['HTTP_X_FORWARDED_PROTO'] ) === 'https' ) return true;
    if ( ! empty( $_SERVER['HTTP_CF_VISITOR'] ) && strpos( (string) $_SERVER['HTTP_CF_VISITOR'], 'https' ) !== false ) return true;
    return false;
}

/** Er WordPress selv satt opp med https-adresse? */
function ikss_home_is_https() {
    return 0 === strpos( home_url(), 'https://' );
}

/**
 * Henter sidens egen forside over https med sertifikatvalidering.
 * Lagrer 'ok' eller 'feil' med tidspunkt og feilmelding.
 */
function ikss_https_selfcheck() {
    $url = set_url_scheme( home_url( '/' ), 'https' );
    $r   = wp_remote_get( $url, [
        'timeout'     => 10,
        'redirection' => 2,
        'sslverify'   => true,
        'headers'     => [ 'User-Agent' => 'IK Site Security selvsjekk' ],
    ] );

    if ( is_wp_error( $r ) ) {
        $status = 'feil';
        $melding = $r->get_error_message();
    } else {
        $code    = (int) wp_remote_retrieve_response_code( $r );
        $status  = ( $code >= 200 && $code < 400 ) ? 'ok' : 'feil';
        $melding = $status === 'ok' ? '' : 'HTTP ' . $code;
    }

    update_option( 'ikss_https_check', $status, false );
    update_option( 'ikss_https_check_time', ikss_now(), false );
    update_option( 'ikss_https_check_message', sanitize_text_field( $melding ), false );
    return $status;
}

/** Er HTTPS-tvangen aktiv akkurat nå på denne siden? */
function ikss_https_is_active() {
    return get_option( 'ikss_force_https', 1 )
        && get_option( 'ikss_https_check' ) === 'ok'
        && ikss_home_is_https();
}

function ikss_https_redirect() {
    if ( ! ikss_https_is_active() ) return;
    if ( ikss_request_is_https() ) return;
    if ( defined( 'WP_CLI' ) || defined( 'DOING_CRON' ) || php_sapi_name() === 'cli' ) return;
    if ( empty( $_SERVER['REQUEST_URI'] ) ) return;

    $host = wp_parse_url( home_url(), PHP_URL_HOST );
    if ( ! $host ) return;

    $uri = (string) $_SERVER['REQUEST_URI'];
    if ( strpos( $uri, '/' ) !== 0 ) $uri = '/' . $uri;

    wp_redirect( 'https://' . $host . $uri, 301 );
    exit;
}

function ikss_https_hsts_header() {
    if ( headers_sent() ) return;
    if ( ! ikss_https_is_active() ) return;
    if ( ! ikss_request_is_https() ) return;
    header( 'Strict-Transport-Security: max-age=86400' );
}

/** Melding i wp-admin når tvangen er ønsket, men ikke aktiv. */
function ikss_https_admin_notice() {
    if ( ! current_user_can( 'manage_options' ) ) return;
    if ( ! get_option( 'ikss_force_https', 1 ) ) return;
    if ( ikss_https_is_active() ) return;

    if ( ! ikss_home_is_https() ) {
        $tekst = 'WordPress sin adresse (Innstillinger → Generelt) er ikke https. HTTPS-tvang er av på denne siden til adressen er endret.';
    } else {
        $melding = get_option( 'ikss_https_check_message', '' );
        $status  = get_option( 'ikss_https_check', '' );
        if ( $status === '' ) {
            $tekst = 'SSL-selvsjekken har ikke kjørt ennå. Den kjører i bakgrunnen om kort tid, eller med en gang hvis du lagrer innstillingene. HTTPS-tvang er av til den har lykkes.';
        } else {
            $tekst = 'SSL-selvsjekken feilet' . ( $melding ? ' (' . $melding . ')' : '' ) . '. HTTPS-tvang er av på denne siden til sertifikatet er i orden. Sjekken kjøres på nytt automatisk hvert døgn, eller når innstillingene lagres.';
        }
    }
    echo '<div class="notice notice-warning"><p><strong>IK Site Security:</strong> ' . esc_html( $tekst ) . '</p></div>';
}
