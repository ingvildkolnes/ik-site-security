<?php
/**
 * Modul: Login-beskyttelse og redirects
 * Basert på samme teknikk som WPS Hide Login.
 */

defined( 'ABSPATH' ) || exit;

add_action( 'plugins_loaded', 'ikss_plugins_loaded', 9999 );
add_action( 'wp_loaded',      'ikss_wp_loaded' );
add_filter( 'site_url',         'ikss_filter_site_url', 10, 4 );
add_filter( 'network_site_url', 'ikss_filter_network_site_url', 10, 3 );
add_filter( 'wp_redirect',      'ikss_filter_wp_redirect', 10, 2 );
remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );

function ikss_login_slug() {
    return sanitize_title( get_option( 'ikss_login_slug', 'portal' ) );
}

function ikss_login_url( $scheme = null ) {
    $base = apply_filters( 'ikss_home_url', home_url( '/', $scheme ) );
    if ( get_option( 'permalink_structure' ) ) {
        return trailingslashit( $base . ikss_login_slug() );
    }
    return $base . '?' . ikss_login_slug();
}

function ikss_use_trailing_slashes() {
    return '/' === substr( get_option( 'permalink_structure' ), -1, 1 );
}

function ikss_trailingslashit( $string ) {
    return ikss_use_trailing_slashes() ? trailingslashit( $string ) : untrailingslashit( $string );
}

function ikss_plugins_loaded() {
    if ( ! get_option( 'ikss_custom_login_enabled', 0 ) ) return;

    global $pagenow;

    $request = parse_url( rawurldecode( $_SERVER['REQUEST_URI'] ) );

    if (
        strpos( rawurldecode( $_SERVER['REQUEST_URI'] ), 'wp-login.php' ) !== false
        && ! is_admin()
    ) {
        $_SERVER['REQUEST_URI'] = ikss_trailingslashit( '/' . str_repeat( '-/', 10 ) );
        $pagenow = 'index.php';

    } elseif (
        ( isset( $request['path'] ) && untrailingslashit( $request['path'] ) === home_url( ikss_login_slug(), 'relative' ) )
        || ( ! get_option( 'permalink_structure' ) && isset( $_GET[ ikss_login_slug() ] ) && empty( $_GET[ ikss_login_slug() ] ) )
    ) {
        $_SERVER['SCRIPT_NAME'] = ikss_login_slug();
        $pagenow = 'wp-login.php';
    }
}

function ikss_wp_loaded() {
    if ( ! get_option( 'ikss_custom_login_enabled', 0 ) ) return;

    global $pagenow;

    $request = parse_url( rawurldecode( $_SERVER['REQUEST_URI'] ) );

    if (
        is_admin()
        && ! is_user_logged_in()
        && ! defined( 'WP_CLI' )
        && ! defined( 'DOING_AJAX' )
        && ! defined( 'DOING_CRON' )
        && $pagenow !== 'admin-post.php'
        && ( ! isset( $request['path'] ) || $request['path'] !== '/wp-admin/options.php' )
    ) {
        status_header( 404 );
        nocache_headers();
        ikss_load_404();
        exit;
    }

    if ( $pagenow === 'index.php' && strpos( $_SERVER['REQUEST_URI'], str_repeat( '-/', 10 ) ) !== false ) {
        status_header( 404 );
        nocache_headers();
        ikss_load_404();
        exit;
    }

    if ( $pagenow === 'wp-login.php' ) {
        if ( is_user_logged_in() && ! isset( $_REQUEST['action'] ) ) {
            wp_safe_redirect( admin_url() );
            exit;
        }
        @require_once ABSPATH . 'wp-login.php';
        exit;
    }
}

function ikss_load_404() {
    global $wp_query;
    if ( isset( $wp_query ) ) $wp_query->set_404();

    $template = get_404_template();
    if ( $template && file_exists( $template ) ) {
        require_once $template;
    } else {
        wp_die( 'Side ikke funnet.', '404 – Ikke funnet', [ 'response' => 404 ] );
    }
}

function ikss_filter_wp_login_php( $url, $scheme = null ) {
    // Ikke filtrer i REST API eller AJAX – fikser konflikt med block editor i WP 7
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) return $url;
    if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) return $url;

    if ( strpos( $url, 'wp-login.php?action=postpass' ) !== false ) return $url;
    if ( strpos( $url, 'wp-login.php' ) !== false ) {
        if ( is_ssl() ) $scheme = 'https';
        $args = explode( '?', $url );
        if ( isset( $args[1] ) ) {
            parse_str( $args[1], $args );
            if ( isset( $args['login'] ) ) $args['login'] = rawurlencode( $args['login'] );
            $url = add_query_arg( $args, ikss_login_url( $scheme ) );
        } else {
            $url = ikss_login_url( $scheme );
        }
    }
    return $url;
}

function ikss_filter_site_url( $url, $path, $scheme, $blog_id ) {
    if ( ! get_option( 'ikss_custom_login_enabled', 0 ) ) return $url;
    return ikss_filter_wp_login_php( $url, $scheme );
}

function ikss_filter_network_site_url( $url, $path, $scheme ) {
    if ( ! get_option( 'ikss_custom_login_enabled', 0 ) ) return $url;
    return ikss_filter_wp_login_php( $url, $scheme );
}

function ikss_filter_wp_redirect( $location, $status ) {
    if ( ! get_option( 'ikss_custom_login_enabled', 0 ) ) return $location;
    return ikss_filter_wp_login_php( $location );
}
