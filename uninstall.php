<?php
/**
 * Kjører bare når pluginen SLETTES i wp-admin (ikke ved deaktivering).
 * Fjerner tabeller, innstillinger og .htaccess-blokken. Lagt til i 2.4.0.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

// Bakgrunnsjobben for SSL-selvsjekk.
wp_clear_scheduled_hook( 'ikss_https_selfcheck_event' );

// Tabeller med IP-adresser og User-Agent (personopplysninger).
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}ikss_lockouts" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}ikss_login_log" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}ikss_rest_log" );

// Alle innstillinger som starter med ikss_ (også selvsjekk-status og lås).
$wpdb->query( $wpdb->prepare(
    "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
    $wpdb->esc_like( 'ikss_' ) . '%'
) );

// .htaccess-blokken (fjernes normalt allerede ved deaktivering).
$ikss_htaccess = ABSPATH . '.htaccess';
if ( file_exists( $ikss_htaccess ) && is_writable( $ikss_htaccess ) ) {
    $ikss_current = file_get_contents( $ikss_htaccess );
    $ikss_updated = preg_replace( '/# BEGIN IK Site Security.*?# END IK Site Security\n?/s', '', $ikss_current );
    if ( null !== $ikss_updated && $ikss_updated !== $ikss_current ) {
        file_put_contents( $ikss_htaccess, $ikss_updated );
    }
}
