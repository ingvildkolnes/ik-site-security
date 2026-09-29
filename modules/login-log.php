<?php
/**
 * Modul: Innloggingslogg
 * – Logger vellykkede innlogginger (bruker, IP, tidspunkt, user agent)
 * – Sender e-postvarsel ved innlogging fra ny IP
 * – Logg vises i admin under IK Security
 */

defined( 'ABSPATH' ) || exit;

add_action( 'wp_login', 'ikss_log_login', 10, 2 );

function ikss_log_login( $user_login, $user ) {
    global $wpdb;
    $table = $wpdb->prefix . 'ikss_login_log';
    $ip    = ikss_get_ip();
    $now   = current_time( 'mysql' );
    $agent = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) );
    // Kolonnen er varchar(255). For lang verdi kan stoppe hele loggraden.
    $agent = function_exists( 'mb_substr' ) ? mb_substr( $agent, 0, 255 ) : substr( $agent, 0, 255 );

    // Sjekk om denne IP-en har logget inn før for denne brukeren
    $known = $wpdb->get_var( $wpdb->prepare(
        "SELECT COUNT(*) FROM $table WHERE user_id = %d AND ip = %s",
        $user->ID, $ip
    ) );

    // Logg innloggingen
    $wpdb->insert( $table, [
        'user_id'    => $user->ID,
        'user_login' => $user_login,
        'ip'         => $ip,
        'user_agent' => $agent,
        'logged_at'  => $now,
    ] );

    // Send e-postvarsel hvis ny IP og varsling er skrudd på
    if ( ! $known && get_option( 'ikss_login_alert_enabled', 0 ) ) {
        ikss_send_login_alert( $user, $ip, $now );
    }

    // Behold bare de 200 siste radene
    $wpdb->query(
        "DELETE FROM $table WHERE id NOT IN (
            SELECT id FROM (
                SELECT id FROM $table ORDER BY logged_at DESC LIMIT 200
            ) AS keep
        )"
    );
}

function ikss_send_login_alert( $user, $ip, $time ) {
    $to      = get_option( 'admin_email' );
    $site    = get_bloginfo( 'name' );
    $subject = "[{$site}] Innlogging fra ny IP-adresse";

    $message  = "Hei,\n\n";
    $message .= "Det ble logget inn på {$site} fra en IP-adresse vi ikke har sett før.\n\n";
    $message .= "Bruker:    {$user->user_login}\n";
    $message .= "IP:        {$ip}\n";
    $message .= "Tidspunkt: {$time}\n\n";
    $message .= "Hvis dette var deg, trenger du ikke gjøre noe.\n";
    $message .= "Hvis ikke, bør du endre passord umiddelbart.\n\n";
    $message .= "— IK Site Security\n";
    $message .= get_site_url();

    wp_mail( $to, $subject, $message );
}

function ikss_create_login_log_table() {
    global $wpdb;
    $table   = $wpdb->prefix . 'ikss_login_log';
    $charset = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE IF NOT EXISTS $table (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        user_id bigint(20) NOT NULL,
        user_login varchar(60) NOT NULL,
        ip varchar(45) NOT NULL,
        user_agent varchar(255) DEFAULT '',
        logged_at datetime NOT NULL,
        PRIMARY KEY (id),
        KEY user_id (user_id),
        KEY ip (ip)
    ) $charset;";
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta( $sql );
}
