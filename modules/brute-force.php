<?php
/**
 * Modul: Brute Force-beskyttelse
 * – Teller mislykkede innloggingsforsøk per IP
 * – Låser ute IP etter X forsøk i Y minutter
 * – Admin kan se og tømme lockout-liste
 */

defined( 'ABSPATH' ) || exit;

add_filter( 'authenticate',    'ikss_check_lockout', 1, 3 );  // prioritet 1 = kjører først
add_action( 'wp_login_failed', 'ikss_login_failed' );
add_action( 'wp_login',        'ikss_login_success', 10, 2 );
add_filter( 'login_errors',    'ikss_lockout_error_message' );

function ikss_get_ip() {
    foreach ( [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' ] as $key ) {
        if ( ! empty( $_SERVER[ $key ] ) ) {
            $ip = trim( explode( ',', $_SERVER[ $key ] )[0] );
            if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) return $ip;
        }
    }
    return '0.0.0.0';
}

/* ── Sjekk om IP er låst FØR innlogging forsøkes ─────────── */
function ikss_check_lockout( $user, $username, $password ) {
    if ( ! get_option( 'ikss_brute_force_enabled', 1 ) ) return $user;
    if ( empty( $username ) && empty( $password ) ) return $user;

    global $wpdb;
    $table = $wpdb->prefix . 'ikss_lockouts';
    $ip    = ikss_get_ip();
    $now   = current_time( 'mysql' );

    $row = $wpdb->get_row( $wpdb->prepare(
        "SELECT * FROM $table WHERE ip = %s", $ip
    ) );

    // Rydd opp utgåtte lockouts
    if ( $row && $row->locked_until && $row->locked_until <= $now ) {
        $wpdb->delete( $table, [ 'ip' => $ip ] );
        return $user;
    }

    // Er låst → returner feil
    if ( $row && $row->locked_until && $row->locked_until > $now ) {
        $mins_left = (int) ceil( ( strtotime( $row->locked_until ) - strtotime( $now ) ) / 60 );
        return new WP_Error( 'ikss_locked', sprintf(
            'For mange innloggingsforsøk. Prøv igjen om %d minutt%s.',
            $mins_left,
            $mins_left === 1 ? '' : 'er'
        ) );
    }

    return $user;
}

/* ── Tell mislykkede forsøk ──────────────────────────────── */
function ikss_login_failed( $username ) {
    if ( ! get_option( 'ikss_brute_force_enabled', 1 ) ) return;

    global $wpdb;
    $table   = $wpdb->prefix . 'ikss_lockouts';
    $ip      = ikss_get_ip();
    $max     = (int) get_option( 'ikss_brute_max_attempts', 5 );
    $lockout = (int) get_option( 'ikss_brute_lockout_mins', 30 );
    $now     = current_time( 'mysql' );

    $row = $wpdb->get_row( $wpdb->prepare(
        "SELECT * FROM $table WHERE ip = %s", $ip
    ) );

    if ( $row ) {
        $attempts     = $row->attempts + 1;
        $locked_until = null;
        if ( $attempts >= $max ) {
            $locked_until = date( 'Y-m-d H:i:s', strtotime( "+{$lockout} minutes", strtotime( $now ) ) );
        }
        $wpdb->update( $table,
            [ 'attempts' => $attempts, 'last_attempt' => $now, 'locked_until' => $locked_until ],
            [ 'ip' => $ip ]
        );
    } else {
        $wpdb->insert( $table, [
            'ip'           => $ip,
            'attempts'     => 1,
            'last_attempt' => $now,
            'locked_until' => null,
        ] );
    }
}

/* ── Vis lockout-melding på login-siden ──────────────────── */
function ikss_lockout_error_message( $error ) {
    global $wpdb;
    if ( ! get_option( 'ikss_brute_force_enabled', 1 ) ) return $error;

    $table = $wpdb->prefix . 'ikss_lockouts';
    $ip    = ikss_get_ip();
    $now   = current_time( 'mysql' );

    $row = $wpdb->get_row( $wpdb->prepare(
        "SELECT * FROM $table WHERE ip = %s", $ip
    ) );

    if ( $row && $row->locked_until && $row->locked_until > $now ) {
        $mins_left = (int) ceil( ( strtotime( $row->locked_until ) - strtotime( $now ) ) / 60 );
        return sprintf(
            '<strong>Utestengt:</strong> For mange innloggingsforsøk. Prøv igjen om %d minutt%s.',
            $mins_left,
            $mins_left === 1 ? '' : 'er'
        );
    }

    return $error;
}

/* ── Nullstill ved vellykket innlogging ──────────────────── */
function ikss_login_success( $user_login, $user ) {
    global $wpdb;
    $wpdb->delete( $wpdb->prefix . 'ikss_lockouts', [ 'ip' => ikss_get_ip() ] );
}

/* ── Admin: hent lockouts ────────────────────────────────── */
function ikss_get_lockouts() {
    global $wpdb;
    return $wpdb->get_results(
        "SELECT * FROM {$wpdb->prefix}ikss_lockouts ORDER BY last_attempt DESC LIMIT 50"
    );
}

function ikss_clear_lockout( $ip ) {
    global $wpdb;
    $wpdb->delete( $wpdb->prefix . 'ikss_lockouts', [ 'ip' => $ip ] );
}

add_action( 'admin_init', function() {
    if ( isset( $_POST['ikss_unlock_ip'] ) &&
         current_user_can( 'manage_options' ) &&
         check_admin_referer( 'ikss_unlock', 'ikss_unlock_nonce' ) ) {
        ikss_clear_lockout( sanitize_text_field( $_POST['ikss_unlock_ip'] ) );
        wp_safe_redirect( add_query_arg( 'ikss_unlocked', '1', wp_get_referer() ) );
        exit;
    }
    if ( isset( $_POST['ikss_clear_all_lockouts'] ) &&
         current_user_can( 'manage_options' ) &&
         check_admin_referer( 'ikss_unlock', 'ikss_unlock_nonce' ) ) {
        global $wpdb;
        $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}ikss_lockouts" );
        wp_safe_redirect( add_query_arg( 'ikss_unlocked', 'all', wp_get_referer() ) );
        exit;
    }
} );
