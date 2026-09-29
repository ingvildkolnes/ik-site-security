<?php
/**
 * Plugin Name:  IK Site Security
 * Description:  Modulær sikkerhetsplugin – XML-RPC, versjonsskjuling, brute force, custom login og redirects.
 * Version:      2.4.0
 * Author:       Ingvild Kolnes
 * Update URI:   https://github.com/ingvildkolnes/ik-site-security
 * Text Domain:  ik-site-security
 */

defined( 'ABSPATH' ) || exit;

define( 'IKSS_VERSION',    '2.4.0' );
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
    ];
    foreach ( $defaults as $key => $value ) {
        if ( false === get_option( 'ikss_' . $key ) ) {
            update_option( 'ikss_' . $key, $value );
        }
    }
    ikss_create_lockout_table();
    ikss_create_login_log_table();
    ikss_write_htaccess();
    flush_rewrite_rules();
    update_option( 'ikss_version', IKSS_VERSION );
}

/* ---------------------------------------------------------------
 * Oppgradering (2.4.0)
 * Automatiske oppdateringer kjører ikke aktiveringskoden. Derfor
 * sjekkes lagret versjon én gang, og det som ellers bare skjer ved
 * aktivering, gjøres på nytt ved første besøk etter oppdatering.
 * ------------------------------------------------------------- */
add_action( 'init', 'ikss_maybe_upgrade', 99 );

function ikss_maybe_upgrade() {
    if ( get_option( 'ikss_version' ) === IKSS_VERSION ) return;

    ikss_create_lockout_table();
    ikss_create_login_log_table();
    ikss_refresh_htaccess();     // skriver .htaccess-reglene med ny syntaks
    flush_rewrite_rules();       // fjerner rewrite-regelen fra gamle login.php

    update_option( 'ikss_version', IKSS_VERSION );
}

function ikss_deactivate() {
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
