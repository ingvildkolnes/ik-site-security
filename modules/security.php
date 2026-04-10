<?php
/**
 * Modul: Sikkerhet
 * – XML-RPC blokkert (htaccess + filter)
 * – WP-versjon fjernet
 * – Sikkerhetstoppfiler
 * – Blokkere author-scanning
 * – Beskytte wp-config.php og .htaccess
 */

defined( 'ABSPATH' ) || exit;

add_action( 'init', 'ikss_security_init' );

function ikss_security_init() {

    // ── XML-RPC ──────────────────────────────────────────────
    if ( get_option( 'ikss_disable_xmlrpc', 1 ) ) {
        add_filter( 'xmlrpc_enabled', '__return_false' );
        add_filter( 'xmlrpc_methods', function() { return []; } );
    }

    // ── WP-versjon ───────────────────────────────────────────
    if ( get_option( 'ikss_remove_wp_version', 1 ) ) {
        remove_action( 'wp_head', 'wp_generator' );
        add_filter( 'the_generator', '__return_empty_string' );
        add_filter( 'style_loader_src',  'ikss_remove_version_query', 999 );
        add_filter( 'script_loader_src', 'ikss_remove_version_query', 999 );
    }

    // ── RSD og WLW ───────────────────────────────────────────
    if ( get_option( 'ikss_remove_rsd_link', 1 ) ) {
        remove_action( 'wp_head', 'rsd_link' );
    }
    if ( get_option( 'ikss_remove_wlw_link', 1 ) ) {
        remove_action( 'wp_head', 'wlw_manifest_link' );
    }

    // ── Innloggingsfeil ──────────────────────────────────────
    // Brute force-modulen håndterer lockout-meldingen – denne skjuler alt annet
    if ( get_option( 'ikss_hide_login_errors', 1 ) ) {
        add_filter( 'login_errors', '__return_empty_string', 5 );
    }

    // ── Fillredigering ───────────────────────────────────────
    if ( get_option( 'ikss_disable_file_edit', 1 ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
        define( 'DISALLOW_FILE_EDIT', true );
    }

    // ── Author-scanning blokkering ───────────────────────────
    if ( get_option( 'ikss_block_author_scan', 1 ) ) {
        if ( ! is_admin() && isset( $_GET['author'] ) ) {
            wp_safe_redirect( home_url( '/' ), 301 );
            exit;
        }
    }

    // ── Sikkerhetstoppfiler ──────────────────────────────────
    add_action( 'send_headers', 'ikss_security_headers' );
}

function ikss_remove_version_query( $src ) {
    if ( strpos( $src, 'ver=' ) ) {
        $src = remove_query_arg( 'ver', $src );
    }
    return $src;
}

function ikss_security_headers() {
    if ( headers_sent() ) return;
    header( 'X-Content-Type-Options: nosniff' );
    header( 'X-Frame-Options: SAMEORIGIN' );
    header( 'X-XSS-Protection: 1; mode=block' );
    header( 'Referrer-Policy: strict-origin-when-cross-origin' );
    header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );
}

/* ── .htaccess-håndtering ────────────────────────────────── */

function ikss_write_htaccess() {
    $htaccess = ABSPATH . '.htaccess';
    if ( ! is_writable( $htaccess ) ) return;

    $current = file_get_contents( $htaccess );

    // Ikke skriv dobbelt
    if ( strpos( $current, '# BEGIN IK Site Security' ) !== false ) return;

    $rules = ikss_get_htaccess_rules();
    $new   = $rules . "\n" . $current;
    file_put_contents( $htaccess, $new );
}

function ikss_remove_htaccess() {
    $htaccess = ABSPATH . '.htaccess';
    if ( ! file_exists( $htaccess ) || ! is_writable( $htaccess ) ) return;

    $current = file_get_contents( $htaccess );
    $pattern = '/# BEGIN IK Site Security.*?# END IK Site Security\n?/s';
    $updated = preg_replace( $pattern, '', $current );
    file_put_contents( $htaccess, $updated );
}

function ikss_get_htaccess_rules() {
    $disable_xmlrpc     = get_option( 'ikss_disable_xmlrpc', 1 );
    $protect_sensitive  = get_option( 'ikss_protect_sensitive', 1 );

    $rules = "# BEGIN IK Site Security\n";

    if ( $disable_xmlrpc ) {
        $rules .= "# Blokker XML-RPC\n";
        $rules .= "<Files xmlrpc.php>\n";
        $rules .= "  Order Deny,Allow\n";
        $rules .= "  Deny from all\n";
        $rules .= "</Files>\n\n";
    }

    if ( $protect_sensitive ) {
        $rules .= "# Beskytt wp-config.php\n";
        $rules .= "<Files wp-config.php>\n";
        $rules .= "  Order Deny,Allow\n";
        $rules .= "  Deny from all\n";
        $rules .= "</Files>\n\n";

        $rules .= "# Beskytt .htaccess\n";
        $rules .= "<Files .htaccess>\n";
        $rules .= "  Order Deny,Allow\n";
        $rules .= "  Deny from all\n";
        $rules .= "</Files>\n\n";

        $rules .= "# Blokker tilgang til readme og lisensfiler\n";
        $rules .= "<FilesMatch \"^(readme|license|README|LICENSE)\.(html|txt|md)$\">\n";
        $rules .= "  Order Deny,Allow\n";
        $rules .= "  Deny from all\n";
        $rules .= "</FilesMatch>\n";
    }

    $rules .= "# END IK Site Security\n";
    return $rules;
}

// Oppdater htaccess når innstillinger lagres
add_action( 'update_option_ikss_disable_xmlrpc',    'ikss_refresh_htaccess' );
add_action( 'update_option_ikss_protect_sensitive', 'ikss_refresh_htaccess' );

function ikss_refresh_htaccess() {
    ikss_remove_htaccess();
    ikss_write_htaccess();
}
