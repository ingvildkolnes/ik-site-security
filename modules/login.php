<?php
/**
 * Modul: Custom Login
 * – Virtuell side på valgt slug (standard: /portal)
 * – Bruker wp_signon() i bakgrunnen
 * – Nonce-beskyttelse
 * – Viser brute force-feil fra WP_Error
 */

defined( 'ABSPATH' ) || exit;

add_action( 'init',                  'ikss_login_rewrite' );
add_action( 'template_redirect',     'ikss_login_template' );
add_action( 'wp_enqueue_scripts',    'ikss_login_styles' );

function ikss_login_rewrite() {
    if ( ! get_option( 'ikss_custom_login_enabled', 1 ) ) return;
    $slug = sanitize_title( get_option( 'ikss_login_slug', 'portal' ) );
    add_rewrite_rule( '^' . $slug . '/?$', 'index.php?ikss_login_page=1', 'top' );
    add_rewrite_tag( '%ikss_login_page%', '([^&]+)' );
}

function ikss_login_styles() {
    if ( ! get_query_var( 'ikss_login_page' ) ) return;
    wp_enqueue_style( 'ikss-login', IKSS_URL . 'login/login.css', [], IKSS_VERSION );
}

function ikss_login_template() {
    if ( ! get_query_var( 'ikss_login_page' ) ) return;

    if ( is_user_logged_in() ) {
        wp_safe_redirect( admin_url() );
        exit;
    }

    $error   = '';
    $success = false;

    if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
        if (
            ! isset( $_POST['ikss_nonce'] ) ||
            ! wp_verify_nonce( $_POST['ikss_nonce'], 'ikss_login' )
        ) {
            $error = 'Ugyldig forespørsel. Prøv igjen.';
        } else {
            $creds = [
                'user_login'    => sanitize_user( wp_unslash( $_POST['log'] ?? '' ) ),
                'user_password' => wp_unslash( $_POST['pwd'] ?? '' ),
                'remember'      => isset( $_POST['rememberme'] ),
            ];

            // Kjør gjennom WP authenticate (inkl. brute force-sjekk)
            $user = wp_signon( $creds, is_ssl() );

            if ( is_wp_error( $user ) ) {
                // Bruk brute force-feilmelding hvis det er den, ellers generisk
                $code = $user->get_error_code();
                if ( $code === 'ikss_locked' ) {
                    $error = $user->get_error_message();
                } else {
                    $error = 'Feil brukernavn eller passord.';
                }
            } else {
                wp_safe_redirect( admin_url() );
                exit;
            }
        }
    }

    include IKSS_PATH . 'login/login-template.php';
    exit;
}
