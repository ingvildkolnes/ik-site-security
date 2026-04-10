<?php
/**
 * Plugin Name:  IK Site Security
 * Description:  Modulær sikkerhetsplugin – XML-RPC, versjonsskjuling, brute force, custom login og redirects.
 * Version:      1.7.0
 * Author:       Ingvild Kolnes
 * Text Domain:  ik-site-security
 */

defined( 'ABSPATH' ) || exit;

define( 'IKSS_VERSION', '1.7.0' );
define( 'IKSS_PATH',    plugin_dir_path( __FILE__ ) );
define( 'IKSS_URL',     plugin_dir_url( __FILE__ ) );
define( 'IKSS_DB_VERSION', '1' );


/* ---------------------------------------------------------------
 * Plugin Update Checker – henter oppdateringer fra GitHub
 * ------------------------------------------------------------- */
if ( file_exists( IKSS_PATH . 'lib/plugin-update-checker/plugin-update-checker.php' ) ) {
    require_once IKSS_PATH . 'lib/plugin-update-checker/plugin-update-checker.php';
    $update_checker = YahnisElsts\PluginUpdateChecker5\PucFactory::buildUpdateChecker(
        'https://github.com/ingvildkolnes/ik-site-security/',
        __FILE__,
        'ik-site-security'
    );
    $update_checker->setBranch( 'main' );
    $update_checker->getVcsApi()->enableReleaseAssets();
}
require_once IKSS_PATH . 'modules/security.php';
// Brute force håndteres av Patchstack Security
require_once IKSS_PATH . 'modules/login.php';
require_once IKSS_PATH . 'modules/redirects.php';
require_once IKSS_PATH . 'modules/login-log.php';
require_once IKSS_PATH . 'modules/admin.php';

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
        'custom_login_enabled' => 1,
        'login_slug'           => 'portal',

    ];
    foreach ( $defaults as $key => $value ) {
        if ( false === get_option( 'ikss_' . $key ) ) {
            update_option( 'ikss_' . $key, $value );
        }
    }

    // Opprett brute force logg-tabell
    ikss_create_lockout_table();
    ikss_create_login_log_table();

    // Skriv .htaccess-regler
    ikss_write_htaccess();

    flush_rewrite_rules();
}

function ikss_deactivate() {
    // Fjern våre .htaccess-regler
    ikss_remove_htaccess();
    flush_rewrite_rules();
}

function ikss_create_lockout_table() {
    global $wpdb;
    $table = $wpdb->prefix . 'ikss_lockouts';
    $charset = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE IF NOT EXISTS $table (
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
