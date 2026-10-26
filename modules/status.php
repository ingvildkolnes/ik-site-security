<?php
/**
 * Modul: Statusendepunkt (2.5.0)
 * GET /wp-json/ikss/v1/status
 * Åpent, uten nøkkel. Gir bare tilstand, aldri hemmeligheter (ikke
 * login-sluggen, ikke IP-er). Ingen kobling til WebCare Connect.
 */

defined( 'ABSPATH' ) || exit;

add_action( 'rest_api_init', function() {
    register_rest_route( 'ikss/v1', '/status', [
        'methods'             => 'GET',
        'callback'            => 'ikss_status_response',
        'permission_callback' => '__return_true',
    ] );
} );

function ikss_status_response() {
    $ssl = get_option( 'ikss_https_check', '' );
    return rest_ensure_response( [
        'plugin'               => 'ik-site-security',
        'version'              => IKSS_VERSION,
        'custom_login_enabled' => (bool) get_option( 'ikss_custom_login_enabled', 0 ),
        'brute_force_enabled'  => (bool) get_option( 'ikss_brute_force_enabled', 1 ),
        'active_lockouts'      => ikss_count_active_lockouts(),
        'force_https'          => (bool) get_option( 'ikss_force_https', 1 ),
        'https_active'         => (bool) ikss_https_is_active(),
        'ssl_ok'               => $ssl === '' ? null : ( $ssl === 'ok' ),
        'ssl_checked_at'       => get_option( 'ikss_https_check_time', '' ),
        'security_txt'         => (bool) get_option( 'ikss_security_txt_enabled', 1 ),
        'rest_failures_24h'    => ikss_count_rest_failures_24h(),
        'generated'            => ikss_now(),
    ] );
}
