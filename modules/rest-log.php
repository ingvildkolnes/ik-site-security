<?php
/**
 * Modul: REST-feillogg (2.5.0)
 * Logger alle REST-svar med status 401 eller 403: tidspunkt (UTC), IP,
 * rute og status. Gjelder alle ruter, også fra andre plugins, uten at
 * de trenger å vite om denne. Ingen nøkler eller headere lagres.
 */

defined( 'ABSPATH' ) || exit;

add_filter( 'rest_post_dispatch', 'ikss_rest_log_dispatch', 10, 3 );

function ikss_rest_log_table() {
    global $wpdb;
    return $wpdb->prefix . 'ikss_rest_log';
}

function ikss_create_rest_log_table() {
    global $wpdb;
    $table   = ikss_rest_log_table();
    $charset = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE IF NOT EXISTS $table (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        ip varchar(45) NOT NULL,
        route varchar(255) NOT NULL,
        status smallint(6) NOT NULL,
        logged_at datetime NOT NULL,
        PRIMARY KEY (id),
        KEY logged_at (logged_at)
    ) $charset;";
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta( $sql );
}

function ikss_rest_log_dispatch( $result, $server, $request ) {
    if ( ! ( $result instanceof WP_REST_Response ) ) return $result;

    $status = (int) $result->get_status();
    if ( $status !== 401 && $status !== 403 ) return $result;

    global $wpdb;
    $table = ikss_rest_log_table();
    $route = $request instanceof WP_REST_Request ? (string) $request->get_route() : '';
    $route = function_exists( 'mb_substr' ) ? mb_substr( $route, 0, 255 ) : substr( $route, 0, 255 );

    $wpdb->insert( $table, [
        'ip'        => ikss_get_ip(),
        'route'     => $route,
        'status'    => $status,
        'logged_at' => ikss_now(),
    ] );

    // Behold bare de 500 siste radene. Ryddes i snitt hver 20. gang,
    // så en strøm av avviste kall ikke gir en ekstra spørring hver gang.
    if ( mt_rand( 1, 20 ) !== 1 ) return $result;
    $wpdb->query(
        "DELETE FROM $table WHERE id NOT IN (
            SELECT id FROM ( SELECT id FROM $table ORDER BY id DESC LIMIT 500 ) AS behold
        )"
    );

    return $result;
}

/** Siste N rader til admin-visningen. */
function ikss_get_rest_log( $antall = 50 ) {
    global $wpdb;
    $table = ikss_rest_log_table();
    return $wpdb->get_results( $wpdb->prepare(
        "SELECT * FROM $table ORDER BY id DESC LIMIT %d", (int) $antall
    ) );
}

/** Antall feil siste 24 timer. Brukes av statusendepunktet. */
function ikss_count_rest_failures_24h() {
    global $wpdb;
    $table = ikss_rest_log_table();
    return (int) $wpdb->get_var( $wpdb->prepare(
        "SELECT COUNT(*) FROM $table WHERE logged_at > %s",
        ikss_time_add( ikss_now(), -1440 )
    ) );
}
