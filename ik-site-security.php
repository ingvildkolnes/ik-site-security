<?php
/**
 * Plugin Name:  IK Site Security
 * Description:  Modulær sikkerhetsplugin – XML-RPC, versjonsskjuling, brute force, custom login og redirects.
 * Version:      2.5.0
 * Author:       Ingvild Kolnes
 * Update URI:   https://github.com/ingvildkolnes/ik-site-security
 * Text Domain:  ik-site-security
 */

defined( 'ABSPATH' ) || exit;

define( 'IKSS_VERSION',    '2.5.0' );
define( 'IKSS_PATH',       plugin_dir_path( __FILE__ ) );
define( 'IKSS_URL',        plugin_dir_url( __FILE__ ) );
define( 'IKSS_DB_VERSION', '1' );

/* ---------------------------------------------------------------
 * Last inn moduler
 * ------------------------------------------------------------- */
require_once IKSS_PATH . 'modules/updater.php';
require_once IKSS_PATH . 'modules/login-log.php';
require_once IKSS_PATH . 'modules/security.php';
require_once IKSS_PATH . 'modules/brute-force.php';
require_once IKSS_PATH . 'modules/redirects.php';
require_once IKSS_PATH . 'modules/https.php';
require_once IKSS_PATH . 'modules/security-txt.php';
require_once IKSS_PATH . 'modules/rest-log.php';
require_once IKSS_PATH . 'modules/status.php';
require_once IKSS_PATH . 'modules/admin.php';

/* ---------------------------------------------------------------
 * Aktivering / deaktivering
 * ------------------------------------------------------------- */
register_activation_hook( __FILE__, 'ikss_activate' );
register_deactivation_hook( __FILE__, 'ikss_deactivate' );

function ikss_activate() {
    $defaults = [
        'disable_xmlrpc'       => 1,
        'remove_wp_version'    => 1,
        'remove_rsd_link'      => 1,
        'remove_wlw_link'      => 1,
        'disable_file_edit'    => 1,
        'hide_login_errors'    => 1,
        'block_author_scan'    => 1,
        'protect_sensitive'    => 1,
        'custom_login_enabled' => 0,
        'login_slug'           => 'portal',
        'brute_force_enabled'  => 1,
        'brute_max_attempts'   => 5,
        'brute_lockout_mins'   => 30,
        'login_alert_enabled'  => 0,
        // 2.5.0
        'force_https'          => 1,
        'security_txt_enabled' => 1,
        'security_txt_contact' => '',
    ];
    foreach ( $defaults as $key => $value ) {
        if ( false === get_option( 'ikss_' . $key ) ) {
            update_option( 'ikss_' . $key, $value );
        }
    }
    ikss_create_lockout_table();
    ikss_create_login_log_table();
    ikss_create_rest_log_table();
    ikss_write_htaccess();
    flush_rewrite_rules();
    ikss_https_schedule();
    ikss_https_selfcheck();   // aktivering skjer i wp-admin, admin venter gjerne ett sekund
    update_option( 'ikss_version', IKSS_VERSION );
}

/** Standardverdier for innstillinger som er kommet til etter første installasjon. */
function ikss_add_missing_defaults() {
    $nye = [
        'force_https'          => 1,
        'security_txt_enabled' => 1,
        'security_txt_contact' => '',
    ];
    foreach ( $nye as $key => $value ) {
        add_option( 'ikss_' . $key, $value );
    }
}

/* ---------------------------------------------------------------
 * Oppgradering (2.4.0)
 * Automatiske oppdateringer kjører ikke aktiveringskoden. Derfor
 * sjekkes lagret versjon én gang, og det som ellers bare skjer ved
 * aktivering, gjøres på nytt ved første besøk etter oppdatering.
 * ------------------------------------------------------------- */
add_action( 'init', 'ikss_maybe_upgrade', 99 );

function ikss_maybe_upgrade() {
    $lagret = get_option( 'ikss_version' );
    if ( $lagret === IKSS_VERSION ) return;

    // 2.5.0: lås, så to samtidige besøk ikke kjører rutinen dobbelt.
    // add_option er atomisk i databasen. En lås eldre enn to minutter
    // regnes som død (avbrutt kjøring) og tas over.
    global $wpdb;
    if ( ! add_option( 'ikss_upgrade_lock', time(), '', 'no' ) ) {
        $laas = (int) get_option( 'ikss_upgrade_lock', 0 );
        if ( $laas > time() - 120 ) return;
        update_option( 'ikss_upgrade_lock', time(), 'no' );
    }

    ikss_add_missing_defaults();
    ikss_create_lockout_table();
    ikss_create_login_log_table();
    ikss_create_rest_log_table();
    ikss_refresh_htaccess();     // skriver .htaccess-reglene med ny syntaks
    flush_rewrite_rules();       // fjerner rewrite-regelen fra gamle login.php

    // 2.5.0: lockout-tabellen gikk fra lokal tid til UTC. Gamle rader tømmes,
    // de ville uansett utløpt innen et døgn.
    if ( ! $lagret || version_compare( $lagret, '2.5.0', '<' ) ) {
        $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}ikss_lockouts" );
    }

    // Selvsjekken går i bakgrunnen, så den besøkende som utløste
    // oppgraderingen ikke venter på et HTTP-kall.
    ikss_https_selfcheck_soon();

    update_option( 'ikss_version', IKSS_VERSION );
    delete_option( 'ikss_upgrade_lock' );
}

function ikss_deactivate() {
    ikss_https_unschedule();
    ikss_remove_htaccess();
    flush_rewrite_rules();
}

function ikss_create_lockout_table() {
    global $wpdb;
    $table   = $wpdb->prefix . 'ikss_lockouts';
    $charset = $wpdb->get_charset_collate();
    $sql     = "CREATE TABLE IF NOT EXISTS $table (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        ip varchar(45) NOT NULL,
        attempts int(11) NOT NULL DEFAULT 1,
        last_attempt datetime NOT NULL,
        locked_until datetime DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY ip (ip)
    ) $charset;";
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta( $sql );
    update_option( 'ikss_db_version', IKSS_DB_VERSION );
}
