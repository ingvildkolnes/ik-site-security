<?php
/**
 * Modul: Brute Force-beskyttelse
 * – Teller mislykkede innloggingsforsøk per IP
 * – Låser ute IP etter X forsøk i Y minutter
 * – Admin kan se og tømme lockout-liste
 */

defined( 'ABSPATH' ) || exit;

// Prioritet 99 = kjører ETTER WordPress sin egen passordsjekk (prioritet 20).
// Da kan ikke riktig passord overstyre en aktiv lockout.
add_filter( 'authenticate',    'ikss_check_lockout', 99, 3 );
add_action( 'wp_login_failed', 'ikss_login_failed' );
add_action( 'wp_login',        'ikss_login_success', 10, 2 );
add_filter( 'login_errors',    'ikss_lockout_error_message' );

/**
 * Klientens IP. Bruker bare REMOTE_ADDR, som ikke kan settes av den som
 * sender forespørselen. CF-Connecting-IP og X-Forwarded-For kan forfalskes
 * og brukes derfor ikke (endret i 2.4.0).
 */
function ikss_get_ip() {
    $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';
    return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
}

/** Antall forsøk før lockout, alltid 2-20. */
function ikss_brute_max_attempts() {
    return min( 20, max( 2, (int) get_option( 'ikss_brute_max_attempts', 5 ) ) );
}

/** Lockout-tid og telle-vindu i minutter, alltid 5-1440. */
function ikss_brute_lockout_mins() {
    return min( 1440, max( 5, (int) get_option( 'ikss_brute_lockout_mins', 30 ) ) );
}

/**
 * Rydd lockout-tabellen: fjern utløpte lockouts og forsøk eldre enn
 * telle-vinduet. Hold i tillegg tabellen under 1000 rader.
 */
function ikss_cleanup_lockouts() {
    global $wpdb;
    $table  = $wpdb->prefix . 'ikss_lockouts';
    $now    = current_time( 'mysql' );
    $cutoff = date( 'Y-m-d H:i:s', strtotime( '-' . ikss_brute_lockout_mins() . ' minutes', strtotime( $now ) ) );

    $wpdb->query( $wpdb->prepare(
        "DELETE FROM $table WHERE ( locked_until IS NOT NULL AND locked_until <= %s ) OR ( locked_until IS NULL AND last_attempt < %s )",
        $now, $cutoff
    ) );

    $max_rows = 1000;
    $count    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" );
    if ( $count > $max_rows ) {
        $wpdb->query( $wpdb->prepare(
            "DELETE FROM $table WHERE locked_until IS NULL ORDER BY last_attempt ASC LIMIT %d",
            $count - $max_rows
        ) );
    }
}

/* ── Sjekk om IP er låst (etter passordsjekken, se prioritet 99) ── */
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
    $max     = ikss_brute_max_attempts();
    $lockout = ikss_brute_lockout_mins();
    $now     = current_time( 'mysql' );
    $cutoff  = date( 'Y-m-d H:i:s', strtotime( "-{$lockout} minutes", strtotime( $now ) ) );

    ikss_cleanup_lockouts();

    $row = $wpdb->get_row( $wpdb->prepare(
        "SELECT * FROM $table WHERE ip = %s", $ip
    ) );

    // Allerede låst: ikke tell videre, så ventetiden ikke forlenges.
    if ( $row && $row->locked_until && $row->locked_until > $now ) {
        return;
    }

    if ( $row ) {
        // Forrige forsøk er eldre enn telle-vinduet: start tellingen på nytt.
        $attempts     = ( $row->last_attempt < $cutoff ) ? 1 : $row->attempts + 1;
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
