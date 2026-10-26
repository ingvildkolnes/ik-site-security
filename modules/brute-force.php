<?php
/**
 * Modul: Brute Force-beskyttelse
 * – Teller mislykkede innloggingsforsøk per IP
 * – Låser ute IP etter X forsøk i Y minutter
 * – Admin kan se og tømme lockout-liste
 *
 * 2.5.0: all tid i lockout-tabellen er UTC. IP hentes fra CF-Connecting-IP
 * bare når forespørselen faktisk kommer fra Cloudflare. Feil app-passord
 * mot REST API telles og blokkeres på lik linje med wp-login.
 */

defined( 'ABSPATH' ) || exit;

// Prioritet 99 = kjører ETTER WordPress sin egen passordsjekk (prioritet 20).
// Da kan ikke riktig passord overstyre en aktiv lockout.
add_filter( 'authenticate',    'ikss_check_lockout', 99, 3 );
add_action( 'wp_login_failed', 'ikss_login_failed' );
add_action( 'wp_login',        'ikss_login_success', 10, 2 );
add_filter( 'login_errors',    'ikss_lockout_error_message' );

// 2.5.0: app-passord mot REST API (går utenom wp_login_failed).
add_action( 'application_password_failed_authentication', 'ikss_app_password_failed' );
add_filter( 'rest_authentication_errors', 'ikss_rest_block_locked_ip', 1 );

/* ── Tid: alltid UTC i tabellen ──────────────────────────── */

/** Nå i UTC, MySQL-format. */
function ikss_now() {
    return current_time( 'mysql', true );
}

/** Legg minutter til et UTC-tidspunkt. Negativt tall trekker fra. */
function ikss_time_add( $mysql_utc, $minutes ) {
    return gmdate( 'Y-m-d H:i:s', strtotime( $mysql_utc . ' UTC' ) + ( (int) $minutes * 60 ) );
}

/** Vis et UTC-tidspunkt i sidens lokale tid. */
function ikss_time_local( $mysql_utc ) {
    return $mysql_utc ? get_date_from_gmt( $mysql_utc, 'Y-m-d H:i' ) : '';
}

/* ── IP ──────────────────────────────────────────────────── */

/**
 * Cloudflares publiserte IP-områder. Hentet fra cloudflare.com/ips-v4 og
 * cloudflare.com/ips-v6 26.10.2026. Oppdateres med pluginen.
 */
function ikss_cloudflare_ranges() {
    return [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ];
}

/** Er IP-en innenfor CIDR-området? Virker for IPv4 og IPv6. */
function ikss_ip_in_cidr( $ip, $cidr ) {
    if ( strpos( $cidr, '/' ) === false ) return false;
    list( $subnet, $bits ) = explode( '/', $cidr, 2 );
    $ip_bin  = @inet_pton( $ip );
    $net_bin = @inet_pton( $subnet );
    if ( $ip_bin === false || $net_bin === false || strlen( $ip_bin ) !== strlen( $net_bin ) ) return false;

    $bits  = (int) $bits;
    $bytes = intdiv( $bits, 8 );
    $rest  = $bits % 8;

    if ( $bytes > 0 && substr( $ip_bin, 0, $bytes ) !== substr( $net_bin, 0, $bytes ) ) return false;
    if ( $rest === 0 ) return true;

    $mask = ( 0xFF << ( 8 - $rest ) ) & 0xFF;
    return ( ord( $ip_bin[ $bytes ] ) & $mask ) === ( ord( $net_bin[ $bytes ] ) & $mask );
}

function ikss_ip_is_cloudflare( $ip ) {
    foreach ( ikss_cloudflare_ranges() as $cidr ) {
        if ( ikss_ip_in_cidr( $ip, $cidr ) ) return true;
    }
    return false;
}

/**
 * Klientens IP og hvor den kom fra.
 * REMOTE_ADDR kan ikke settes av avsenderen. CF-Connecting-IP brukes bare
 * når REMOTE_ADDR er en Cloudflare-adresse, altså når Cloudflare faktisk
 * står foran og serveren ikke selv har gjenopprettet ekte IP.
 *
 * @return array{ip: string, kilde: string}
 */
function ikss_ip_source() {
    $remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';
    $remote = filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '';

    if ( $remote && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && ikss_ip_is_cloudflare( $remote ) ) {
        $cf = trim( (string) $_SERVER['HTTP_CF_CONNECTING_IP'] );
        if ( filter_var( $cf, FILTER_VALIDATE_IP ) ) {
            return [ 'ip' => $cf, 'kilde' => 'CF-Connecting-IP (REMOTE_ADDR er en Cloudflare-adresse)' ];
        }
    }

    return [ 'ip' => $remote ?: '0.0.0.0', 'kilde' => 'REMOTE_ADDR' ];
}

function ikss_get_ip() {
    $s = ikss_ip_source();
    return $s['ip'];
}

/* ── Innstillinger med grenser ───────────────────────────── */

/** Antall forsøk før lockout, alltid 2-20. */
function ikss_brute_max_attempts() {
    return min( 20, max( 2, (int) get_option( 'ikss_brute_max_attempts', 5 ) ) );
}

/** Lockout-tid og telle-vindu i minutter, alltid 5-1440. */
function ikss_brute_lockout_mins() {
    return min( 1440, max( 5, (int) get_option( 'ikss_brute_lockout_mins', 30 ) ) );
}

/* ── Opprydding ──────────────────────────────────────────── */

/**
 * Rydd lockout-tabellen: fjern utløpte lockouts og forsøk eldre enn
 * telle-vinduet. Hold i tillegg tabellen under 1000 rader.
 */
function ikss_cleanup_lockouts() {
    global $wpdb;
    $table  = $wpdb->prefix . 'ikss_lockouts';
    $now    = ikss_now();
    $cutoff = ikss_time_add( $now, -ikss_brute_lockout_mins() );

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

/* ── Er IP-en låst? ──────────────────────────────────────── */

/**
 * Minutter igjen av en aktiv lockout for IP-en, eller 0.
 * Rydder samtidig bort en utløpt rad.
 */
function ikss_lockout_minutes_left( $ip ) {
    global $wpdb;
    $table = $wpdb->prefix . 'ikss_lockouts';
    $now   = ikss_now();

    $row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table WHERE ip = %s", $ip ) );
    if ( ! $row || ! $row->locked_until ) return 0;

    if ( $row->locked_until <= $now ) {
        $wpdb->delete( $table, [ 'ip' => $ip ] );
        return 0;
    }

    return max( 1, (int) ceil( ( strtotime( $row->locked_until . ' UTC' ) - strtotime( $now . ' UTC' ) ) / 60 ) );
}

function ikss_lockout_message( $mins_left ) {
    return sprintf(
        'For mange innloggingsforsøk. Prøv igjen om %d minutt%s.',
        $mins_left,
        $mins_left === 1 ? '' : 'er'
    );
}

/* ── Sjekk om IP er låst (etter passordsjekken, se prioritet 99) ── */
function ikss_check_lockout( $user, $username, $password ) {
    if ( ! get_option( 'ikss_brute_force_enabled', 1 ) ) return $user;
    if ( empty( $username ) && empty( $password ) ) return $user;

    $mins_left = ikss_lockout_minutes_left( ikss_get_ip() );
    if ( $mins_left > 0 ) {
        return new WP_Error( 'ikss_locked', ikss_lockout_message( $mins_left ) );
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
    $now     = ikss_now();
    $cutoff  = ikss_time_add( $now, -$lockout );

    ikss_cleanup_lockouts();

    $row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table WHERE ip = %s", $ip ) );

    // Allerede låst: ikke tell videre, så ventetiden ikke forlenges.
    if ( $row && $row->locked_until && $row->locked_until > $now ) {
        return;
    }

    if ( $row ) {
        // Forrige forsøk er eldre enn telle-vinduet: start tellingen på nytt.
        $attempts     = ( $row->last_attempt < $cutoff ) ? 1 : $row->attempts + 1;
        $locked_until = null;
        if ( $attempts >= $max ) {
            $locked_until = ikss_time_add( $now, $lockout );
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

/* ── App-passord mot REST API (2.5.0) ────────────────────── */

/** Feil app-passord teller som et mislykket innloggingsforsøk. */
function ikss_app_password_failed( $error ) {
    ikss_login_failed( '' );
}

/**
 * Låst IP får 401 på REST-kall som sender Basic Auth. Kjører tidlig i
 * rest_authentication_errors, før WordPress eventuelt har godtatt passordet.
 */
function ikss_rest_block_locked_ip( $result ) {
    if ( ! get_option( 'ikss_brute_force_enabled', 1 ) ) return $result;

    $har_basic = ! empty( $_SERVER['PHP_AUTH_USER'] )
        || ( ! empty( $_SERVER['HTTP_AUTHORIZATION'] ) && stripos( $_SERVER['HTTP_AUTHORIZATION'], 'basic ' ) === 0 );
    if ( ! $har_basic ) return $result;

    $mins_left = ikss_lockout_minutes_left( ikss_get_ip() );
    if ( $mins_left > 0 ) {
        return new WP_Error( 'ikss_locked', ikss_lockout_message( $mins_left ), [ 'status' => 401 ] );
    }
    return $result;
}

/* ── Vis lockout-melding på login-siden ──────────────────── */
function ikss_lockout_error_message( $error ) {
    if ( ! get_option( 'ikss_brute_force_enabled', 1 ) ) return $error;

    $mins_left = ikss_lockout_minutes_left( ikss_get_ip() );
    if ( $mins_left > 0 ) {
        return '<strong>Utestengt:</strong> ' . esc_html( ikss_lockout_message( $mins_left ) );
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

/** Antall aktive lockouts akkurat nå. Brukes av statusendepunktet. */
function ikss_count_active_lockouts() {
    global $wpdb;
    return (int) $wpdb->get_var( $wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->prefix}ikss_lockouts WHERE locked_until IS NOT NULL AND locked_until > %s",
        ikss_now()
    ) );
}

function ikss_clear_lockout( $ip ) {
    global $wpdb;
    $wpdb->delete( $wpdb->prefix . 'ikss_lockouts', [ 'ip' => $ip ] );
}

add_action( 'admin_init', function() {
    if ( isset( $_POST['ikss_unlock_ip'] ) &&
         current_user_can( 'manage_options' ) &&
         check_admin_referer( 'ikss_unlock', 'ikss_unlock_nonce' ) ) {
        ikss_clear_lockout( sanitize_text_field( wp_unslash( $_POST['ikss_unlock_ip'] ) ) );
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
