<?php
/**
 * Modul: Admin-innstillinger
 * Seksjoner: Sikkerhet / Login / Redirects (info)
 */

defined( 'ABSPATH' ) || exit;

add_action( 'admin_menu',            'ikss_admin_menu' );
add_action( 'admin_init',            'ikss_admin_settings' );
add_action( 'admin_enqueue_scripts', 'ikss_admin_styles' );

function ikss_admin_menu() {
    add_options_page(
        'IK Site Security',
        'IK Security',
        'manage_options',
        'ik-site-security',
        'ikss_admin_page'
    );
}

function ikss_admin_styles( $hook ) {
    if ( 'settings_page_ik-site-security' !== $hook ) return;
    wp_enqueue_style( 'ikss-admin', IKSS_URL . 'login/admin.css', [], IKSS_VERSION );
}

function ikss_admin_settings() {
    $fields = [
        'disable_xmlrpc', 'remove_wp_version', 'remove_rsd_link', 'remove_wlw_link',
        'disable_file_edit', 'hide_login_errors', 'block_author_scan', 'protect_sensitive',
        'custom_login_enabled', 'login_slug',
    ];
    foreach ( $fields as $field ) {
        register_setting( 'ikss_settings', 'ikss_' . $field, [
            'sanitize_callback' => $field === 'login_slug' ? 'sanitize_title' : 'absint',
        ] );
    }
}

function ikss_admin_page() {
    if ( ! current_user_can( 'manage_options' ) ) return;
    $slug = get_option( 'ikss_login_slug', 'portal' );
    ?>
    <div class="wrap ikss-wrap">
        <h1 class="ikss-title">🔒 IK Site Security</h1>
        <?php settings_errors(); ?>

        <form method="post" action="options.php">
            <?php settings_fields( 'ikss_settings' ); ?>

            <!-- ══ DEL 1: SIKKERHET ══════════════════════════════ -->
            <div class="ikss-section">
                <h2 class="ikss-section-title"><span class="ikss-icon">🛡️</span> Del 1 — Sikkerhet</h2>
                <table class="form-table ikss-table">
                    <?php ikss_checkbox( 'disable_xmlrpc', 'Deaktiver XML-RPC',
                        'Blokkerer xmlrpc.php på servernivå via .htaccess.' ); ?>
                    <?php ikss_checkbox( 'protect_sensitive', 'Beskytt sensitive filer',
                        'Blokkerer direkte tilgang til wp-config.php, .htaccess og readme/lisensfiler.' ); ?>
                    <?php ikss_checkbox( 'remove_wp_version', 'Fjern WP-versjon',
                        'Fjerner versjonsnummeret fra head, RSS og alle script/style-URLer.' ); ?>
                    <?php ikss_checkbox( 'remove_rsd_link', 'Fjern RSD-lenke',
                        'Fjerner Really Simple Discovery fra head.' ); ?>
                    <?php ikss_checkbox( 'remove_wlw_link', 'Fjern WLW Manifest',
                        'Fjerner Windows Live Writer manifest-lenken.' ); ?>
                    <?php ikss_checkbox( 'disable_file_edit', 'Deaktiver filredigering',
                        'Setter DISALLOW_FILE_EDIT – forhindrer redigering av tema/plugin-filer i admin.' ); ?>
                    <?php ikss_checkbox( 'hide_login_errors', 'Skjul innloggingsfeil',
                        'Erstatter spesifikke WP-feilmeldinger med en nøytral tekst.' ); ?>
                    <?php ikss_checkbox( 'block_author_scan', 'Blokker author-scanning',
                        'Redirecter ?author=1 til forsiden. Forhindrer enumerering av brukernavn.' ); ?>
                </table>
            </div>

            <!-- ══ DEL 2: LOGIN ══════════════════════════════════ -->
            <div class="ikss-section">
                <h2 class="ikss-section-title"><span class="ikss-icon">🔑</span> Del 2 — Custom Login</h2>
                <table class="form-table ikss-table">
                    <?php ikss_checkbox( 'custom_login_enabled', 'Aktiver custom login',
                        'Skjuler wp-login.php og wp-admin. Login skjer på din valgte URL.' ); ?>
                    <tr>
                        <th scope="row"><label for="ikss_login_slug">Login URL</label></th>
                        <td>
                            <div class="ikss-slug-row">
                                <span class="ikss-slug-base"><?php echo esc_url( home_url( '/' ) ); ?></span>
                                <input type="text" id="ikss_login_slug" name="ikss_login_slug"
                                    value="<?php echo esc_attr( $slug ); ?>"
                                    class="regular-text ikss-slug-input" placeholder="portal" />
                            </div>
                            <p class="description">
                                Login-siden: <strong><?php echo esc_url( home_url( '/' . $slug . '/' ) ); ?></strong>
                            </p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- ══ DEL 3: REDIRECTS ══════════════════════════════ -->
            <div class="ikss-section">
                <h2 class="ikss-section-title"><span class="ikss-icon">↩️</span> Del 3 — Redirects</h2>
                <div class="ikss-info-box">
                    <p>Når custom login er aktiv skjer følgende automatisk:</p>
                    <ul>
                        <li>✅ <code>/wp-login.php</code> gir 404</li>
                        <li>✅ <code>/wp-admin</code> gir 404 når ikke innlogget</li>
                        <li>✅ Passordtilbakestilling og utlogging fungerer normalt</li>
                        <li>✅ AJAX og cron blokkeres ikke</li>
                    </ul>
                    <p class="ikss-warning">
                        ⚠️ Husk å flush permalinks etter endringer (Innstillinger → Permalinks → Lagre).
                        Test alltid i inkognito mens du er innlogget i en annen fane.
                    </p>
                </div>
            </div>

            <?php submit_button( 'Lagre innstillinger', 'primary ikss-save-btn' ); ?>
        </form>

        <!-- ══ INNLOGGINGSLOGG ══════════════════════════════════ -->
        <div class="ikss-section ikss-lockout-section">
            <h2 class="ikss-section-title"><span class="ikss-icon">📋</span> Innloggingslogg</h2>
            <?php
            global $wpdb;
            $logs = $wpdb->get_results(
                "SELECT * FROM {$wpdb->prefix}ikss_login_log ORDER BY logged_at DESC LIMIT 50"
            );
            if ( empty( $logs ) ) :
            ?>
                <p class="ikss-muted">Ingen innlogginger registrert ennå.</p>
            <?php else : ?>
                <table class="widefat ikss-lockout-table">
                    <thead>
                        <tr>
                            <th>Bruker</th>
                            <th>IP-adresse</th>
                            <th>Tidspunkt</th>
                            <th>Nettleser</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ( $logs as $row ) : ?>
                        <tr>
                            <td><strong><?php echo esc_html( $row->user_login ); ?></strong></td>
                            <td><code><?php echo esc_html( $row->ip ); ?></code></td>
                            <td><?php echo esc_html( $row->logged_at ); ?></td>
                            <td><span class="ikss-muted"><?php echo esc_html( substr( $row->user_agent, 0, 60 ) ); ?><?php echo strlen( $row->user_agent ) > 60 ? '...' : ''; ?></span></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <p class="ikss-muted" style="margin-top:.75rem;font-size:.8125rem;">Viser de 50 siste. Loggen beholder totalt 200 innlogginger.</p>
            <?php endif; ?>
        </div>

    </div>
    <?php
}

function ikss_checkbox( $key, $label, $description ) {
    $option = get_option( 'ikss_' . $key, 0 );
    ?>
    <tr>
        <th scope="row"><?php echo esc_html( $label ); ?></th>
        <td>
            <label class="ikss-toggle">
                <input type="checkbox" name="ikss_<?php echo esc_attr( $key ); ?>"
                    value="1" <?php checked( 1, $option ); ?> />
                <span class="ikss-toggle-slider"></span>
            </label>
            <p class="description"><?php echo wp_kses_post( $description ); ?></p>
        </td>
    </tr>
    <?php
}
