<?php
/**
 * Modul: security.txt (2.5.0, RFC 9116)
 * Serveres virtuelt på /.well-known/security.txt og /security.txt.
 * Ingen fil skrives til rotmappa. Expires settes seks måneder fram ved
 * hver forespørsel og fornyer seg dermed selv, uten cron.
 */

defined( 'ABSPATH' ) || exit;

add_action( 'init', 'ikss_security_txt_serve', 1 );

function ikss_security_txt_contact() {
    $kontakt = trim( (string) get_option( 'ikss_security_txt_contact', '' ) );
    if ( ! is_email( $kontakt ) ) {
        $kontakt = get_option( 'admin_email' );
    }
    return $kontakt;
}

function ikss_security_txt_body() {
    $linjer = [
        'Contact: mailto:' . ikss_security_txt_contact(),
        'Expires: ' . gmdate( 'Y-m-d\TH:i:s\Z', time() + 180 * DAY_IN_SECONDS ),
        'Canonical: ' . home_url( '/.well-known/security.txt' ),
        'Preferred-Languages: no, en',
    ];
    return implode( "\n", $linjer ) . "\n";
}

function ikss_security_txt_serve() {
    if ( ! get_option( 'ikss_security_txt_enabled', 1 ) ) return;
    if ( empty( $_SERVER['REQUEST_URI'] ) ) return;

    $sti = (string) wp_parse_url( (string) $_SERVER['REQUEST_URI'], PHP_URL_PATH );

    // Installasjon i undermappe: fjern mappenavnet fra stien.
    $hjem = (string) wp_parse_url( home_url(), PHP_URL_PATH );
    $hjem = rtrim( $hjem, '/' );
    if ( $hjem && strpos( $sti, $hjem ) === 0 ) {
        $sti = substr( $sti, strlen( $hjem ) );
    }

    if ( $sti !== '/.well-known/security.txt' && $sti !== '/security.txt' ) return;

    status_header( 200 );
    header( 'Content-Type: text/plain; charset=utf-8' );
    header( 'Cache-Control: public, max-age=3600' );
    echo ikss_security_txt_body();
    exit;
}
