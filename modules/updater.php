<?php
/**
 * Modul: GitHub Auto-Updater
 * Native WordPress-løsning uten tredjeparts bibliotek.
 */

defined( 'ABSPATH' ) || exit;

add_filter( 'update_plugins_github.com', 'ikss_check_github_update', 10, 4 );

function ikss_check_github_update( $update, $plugin_data, $plugin_file, $locales ) {

    $this_plugin = plugin_basename( IKSS_PATH . 'ik-site-security.php' );

    if ( $this_plugin !== $plugin_file ) {
        return $update;
    }

    $response = wp_remote_get(
        'https://api.github.com/repos/ingvildkolnes/ik-site-security/releases/latest',
        [
            'headers' => [
                'Accept'     => 'application/vnd.github.v3+json',
                'User-Agent' => 'WordPress/' . get_bloginfo( 'version' ),
            ],
            'timeout' => 10,
        ]
    );

    if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
        return $update;
    }

    $release = json_decode( wp_remote_retrieve_body( $response ), true );

    if ( empty( $release['tag_name'] ) ) {
        return $update;
    }

    $latest_version = ltrim( $release['tag_name'], 'v' );

    $package_url = '';
    if ( ! empty( $release['assets'] ) ) {
        foreach ( $release['assets'] as $asset ) {
            if ( isset( $asset['name'] ) && substr( $asset['name'], -4 ) === '.zip' ) {
                $package_url = $asset['browser_download_url'];
                break;
            }
        }
    }

    if ( empty( $package_url ) ) {
        return $update;
    }

    if ( ! version_compare( $latest_version, $plugin_data['Version'], '>' ) ) {
        return $update;
    }

    return [
        'id'           => 'github.com/ingvildkolnes/ik-site-security',
        'slug'         => dirname( $plugin_file ),
        'version'      => $latest_version,
        'url'          => 'https://github.com/ingvildkolnes/ik-site-security',
        'package'      => $package_url,
        'requires_php' => '7.4',
    ];
}

/* ── Debug (kun admin, kun når ?ikss_debug=1 i URL) ─────── */
add_action( 'admin_notices', 'ikss_updater_debug' );

function ikss_updater_debug() {
    if ( ! current_user_can( 'manage_options' ) ) return;
    if ( ! isset( $_GET['ikss_debug'] ) ) return;

    $this_plugin      = plugin_basename( IKSS_PATH . 'ik-site-security.php' );
    $installed        = get_plugin_data( WP_PLUGIN_DIR . '/' . $this_plugin );
    $installed_version = $installed['Version'] ?? 'ukjent';

    $response = wp_remote_get(
        'https://api.github.com/repos/ingvildkolnes/ik-site-security/releases/latest',
        [
            'headers' => [
                'Accept'     => 'application/vnd.github.v3+json',
                'User-Agent' => 'WordPress/' . get_bloginfo( 'version' ),
            ],
        ]
    );

    echo '<div class="notice notice-info"><p><strong>IK Security – Updater Debug</strong></p><ul>';
    echo '<li><strong>Plugin file (basename):</strong> ' . esc_html( $this_plugin ) . '</li>';
    echo '<li><strong>Installert versjon:</strong> ' . esc_html( $installed_version ) . '</li>';

    // 2.5.0: hvilken IP pluginen faktisk bruker, og hvorfor.
    $ikss_src = ikss_ip_source();
    echo '<li><strong>IP pluginen bruker:</strong> ' . esc_html( $ikss_src['ip'] ) . ' (kilde: ' . esc_html( $ikss_src['kilde'] ) . ')</li>';
    echo '<li><strong>HTTPS-tvang aktiv:</strong> ' . ( ikss_https_is_active() ? 'ja' : 'nei' ) . ' (selvsjekk: ' . esc_html( get_option( 'ikss_https_check', 'ikke kjørt' ) ) . ')</li>';

    // 2.4.0: vis hvilken IP serveren ser.
    foreach ( [ 'REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP' ] as $ikss_key ) {
        $ikss_val = isset( $_SERVER[ $ikss_key ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $ikss_key ] ) ) : '(ikke satt)';
        echo '<li><strong>' . esc_html( $ikss_key ) . ':</strong> ' . esc_html( $ikss_val ) . '</li>';
    }

    if ( is_wp_error( $response ) ) {
        echo '<li><strong>GitHub API feil:</strong> ' . esc_html( $response->get_error_message() ) . '</li>';
    } else {
        $release = json_decode( wp_remote_retrieve_body( $response ), true );
        $tag     = $release['tag_name'] ?? 'ikke funnet';
        $zip     = '';
        foreach ( $release['assets'] ?? [] as $asset ) {
            if ( substr( $asset['name'], -4 ) === '.zip' ) {
                $zip = $asset['browser_download_url'];
                break;
            }
        }
        echo '<li><strong>GitHub tag_name:</strong> ' . esc_html( $tag ) . '</li>';
        echo '<li><strong>Package URL:</strong> ' . esc_html( $zip ?: 'ikke funnet' ) . '</li>';
    }

    echo '</ul></div>';
}
