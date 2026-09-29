<?php
/**
 * Modul: Admin-innstillinger
 * Seksjoner: Sikkerhet / Brute Force / Login / Redirects (info) / Lockout-liste
 */

defined( 'ABSPATH' ) || exit;

add_action( 'admin_menu',            'ikss_admin_menu' );
// Flush permalinks automatisk når login-slug eller custom login endres
add_action( 'update_option_ikss_login_slug',           'ikss_flush_on_change' );
add_action( 'update_option_ikss_custom_login_enabled', 'ikss_flush_on_change' );

function ikss_flush_on_change() {
    flush_rewrite_rules();
}

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
        'custom_login_enabled', 'login_slug', 'login_alert_enabled',
        'brute_force_enabled', 'brute_max_attempts', 'brute_lockout_mins',
    ];
    foreach ( $fields as $field ) {
        switch ( $field ) {
            case 'login_slug':
                $sanitize = 'ikss_sanitize_login_slug';
                break;
            case 'brute_max_attempts':
                $sanitize = 'ikss_sanitize_max_attempts';
                break;
            case 'brute_lockout_mins':
                $sanitize = 'ikss_sanitize_lockout_mins';
                break;
            default:
                $sanitize = 'ikss_sanitize_checkbox';
        }
        register_setting( 'ikss_settings', 'ikss_' . $field, [ 'sanitize_callback' => $sanitize ] );
    }
}

/** Av/på-felt: alltid 0 eller 1. */
function ikss_sanitize_checkbox( $value ) {
    return empty( $value ) ? 0 : 1;
}

/** Antall forsøk før lockout: 2-20, samme grenser som skjemafeltet. */
function ikss_sanitize_max_attempts( $value ) {
    return min( 20, max( 2, absint( $value ) ) );
}

/** Lockout-tid i minutter: 5-1440, samme grenser som skjemafeltet. */
function ikss_sanitize_lockout_mins( $value ) {
    return min( 1440, max( 5, absint( $value ) ) );
}

function ikss_admin_page() {
    if ( ! current_user_can( 'manage_options' ) ) return;

    $slug     = get_option( 'ikss_login_slug', 'portal' );
    $max      = get_option( 'ikss_brute_max_attempts', 5 );
    $mins     = get_option( 'ikss_brute_lockout_mins', 30 );
    $lockouts = ikss_get_lockouts();
    $now      = current_time( 'mysql' );
    ?>
    <div class="wrap ikss-wrap">
        <h1 class="ikss-title">🔒 IK Site Security</h1>
        <?php settings_errors(); ?>
        <?php if ( isset( $_GET['ikss_unlocked'] ) ) : ?>
            <div class="notice notice-success is-dismissible"><p>
                <?php echo $_GET['ikss_unlocked'] === 'all' ? 'Alle lockouts er fjernet.' : 'IP-adressen er låst opp.'; ?>
            </p></div>
        <?php endif; ?>

        <form method="post" action="options.php">
            <?php settings_fields( 'ikss_settings' ); ?>

            <!-- ══ DEL 1: SIKKERHET ══════════════════════════════ -->
            <div class="ikss-section">
                <h2 class="ikss-section-title"><span class="ikss-icon">🛡️</span> Del 1 — Sikkerhet</h2>
                <table class="form-table ikss-table">
                    <?php ikss_checkbox( 'disable_xmlrpc', 'Deaktiver XML-RPC',
                        'Blokkerer xmlrpc.php på servernivå via .htaccess og deaktiverer WordPress-filteret. BlogVault bruker sin egen plugin og trenger ikke XML-RPC.' ); ?>
                    <?php ikss_checkbox( 'protect_sensitive', 'Beskytt sensitive filer',
                        'Blokkerer direkte tilgang til wp-config.php, .htaccess og readme/lisensfiler via .htaccess.' ); ?>
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
                        'Redirecter ?author=1 til forsiden og skjuler brukerlisten i REST API (/wp-json/wp/v2/users) for utloggede. Forhindrer enumerering av brukernavn.' ); ?>
                </table>
            </div>

            <!-- ══ DEL 2: BRUTE FORCE ════════════════════════════ -->
            <div class="ikss-section">
                <h2 class="ikss-section-title"><span class="ikss-icon">🔐</span> Del 2 — Brute Force-beskyttelse</h2>
                <table class="form-table ikss-table">
                    <?php ikss_checkbox( 'brute_force_enabled', 'Aktiver brute force-beskyttelse',
                        'Låser ute IP-adresser som overskrider maks antall innloggingsforsøk.' ); ?>
                    <tr>
                        <th scope="row"><label for="ikss_brute_max_attempts">Maks forsøk før lockout</label></th>
                        <td>
                            <input type="number" id="ikss_brute_max_attempts" name="ikss_brute_max_attempts"
                                value="<?php echo esc_attr( $max ); ?>" min="2" max="20" class="small-text" />
                            <p class="description">Antall mislykkede forsøk før IP-en låses ute. Standard: 5.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ikss_brute_lockout_mins">Lockout-varighet (minutter)</label></th>
                        <td>
                            <input type="number" id="ikss_brute_lockout_mins" name="ikss_brute_lockout_mins"
                                value="<?php echo esc_attr( $mins ); ?>" min="5" max="1440" class="small-text" />
                            <p class="description">Hvor lenge en IP er utestengt. Feilforsøk telles også bare innenfor dette tidsrommet. Standard: 30 minutter.</p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- ══ DEL 3: LOGIN ══════════════════════════════════ -->
            <div class="ikss-section">
                <h2 class="ikss-section-title"><span class="ikss-icon">🔑</span> Del 3 — Custom Login</h2>
                <table class="form-table ikss-table">
                    <?php ikss_checkbox( 'custom_login_enabled', 'Aktiver custom login-side',
                        'Skjuler wp-login.php og wp-admin. Login skjer på din valgte URL.' ); ?>
                    <tr>
                        <th scope="row"><label for="ikss_login_slug">Login URL-slug</label></th>
                        <td>
                            <div class="ikss-slug-row">
                                <span class="ikss-slug-base"><?php echo esc_url( home_url( '/' ) ); ?></span>
                                <input type="text" id="ikss_login_slug" name="ikss_login_slug"
                                    value="<?php echo esc_attr( $slug ); ?>"
                                    class="regular-text ikss-slug-input" placeholder="portal" />
                            </div>
                            <p class="description">
                                Innloggingssiden: <strong><?php echo esc_url( home_url( '/' . $slug . '/' ) ); ?></strong><br>
                                Velg en slug som er vanskelig å gjette. Unngå åpenbare ord som <code>login</code>, <code>admin</code> eller <code>innlogging</code>.
                            </p>
                        </td>
                    </tr>
                </table>
                <div class="ikss-info-box" style="margin-top:1rem;">
                    <p>Når custom login er aktiv skjer følgende automatisk:</p>
                    <ul>
                        <li>✅ <code>/wp-login.php</code> gir 404 (siden finnes ikke)</li>
                        <li>✅ <code>/wp-admin</code> når ikke innlogget gir 404</li>
                        <li>✅ Passordtilbakestilling, utlogging og AJAX slipper gjennom</li>
                        <li>✅ WP-CLI og cron blokkeres ikke</li>
                    </ul>
                    <p class="ikss-warning">
                        ⚠️ Etter aktivering: Åpne et inkognitovindu og test at innlogging fungerer. Da er du fortsatt innlogget her og kan skru det av igjen om du låser deg selv ute under testen.
                    </p>
                </div>
            </div>

            <?php submit_button( 'Lagre innstillinger', 'primary ikss-save-btn' ); ?>
        </form>

        <!-- ══ LOCKOUT-LISTE ═════════════════════════════════════ -->
        <div class="ikss-section ikss-lockout-section">
            <h2 class="ikss-section-title"><span class="ikss-icon">🚫</span> Aktive lockouts</h2>
            <?php if ( empty( $lockouts ) ) : ?>
                <p class="ikss-muted">Ingen registrerte innloggingsforsøk.</p>
            <?php else : ?>
                <form method="post">
                    <?php wp_nonce_field( 'ikss_unlock', 'ikss_unlock_nonce' ); ?>
                    <table class="widefat ikss-lockout-table">
                        <thead>
                            <tr>
                                <th>IP-adresse</th>
                                <th>Forsøk</th>
                                <th>Siste forsøk</th>
                                <th>Låst ut til</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ( $lockouts as $row ) :
                            $is_locked = $row->locked_until && $row->locked_until > $now;
                        ?>
                            <tr class="<?php echo $is_locked ? 'ikss-row-locked' : ''; ?>">
                                <td><code><?php echo esc_html( $row->ip ); ?></code></td>
                                <td><?php echo (int) $row->attempts; ?></td>
                                <td><?php echo esc_html( $row->last_attempt ); ?></td>
                                <td>
                                    <?php if ( $is_locked ) : ?>
                                        <span class="ikss-badge-locked">🔒 <?php echo esc_html( $row->locked_until ); ?></span>
                                    <?php else : ?>
                                        <span class="ikss-muted">—</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <button type="submit" name="ikss_unlock_ip"
                                        value="<?php echo esc_attr( $row->ip ); ?>"
                                        class="button button-small">Fjern</button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <p>
                        <button type="submit" name="ikss_clear_all_lockouts" value="1"
                            class="button button-secondary"
                            onclick="return confirm('Fjerne alle lockouts?')">
                            Tøm hele listen
                        </button>
                    </p>
                </form>
            <?php endif; ?>
        </div>

        <!-- ══ INNLOGGINGSLOGG ══════════════════════════════════ -->
        <div class="ikss-section ikss-lockout-section">
            <h2 class="ikss-section-title"><span class="ikss-icon">📋</span> Innloggingslogg</h2>
                <table class="form-table ikss-table">
                    <?php ikss_checkbox( 'login_alert_enabled', 'E-postvarsel ved innlogging fra ny IP',
                        'Sender e-post til admin når noen logger inn fra en IP-adresse som ikke er sett før.' ); ?>
                </table>
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
                            <td><span class="ikss-muted"><?php echo esc_html( substr( $row->user_agent, 0, 60 ) ); ?><?php echo strlen( $row->user_agent ) > 60 ? "..." : ""; ?></span></td>
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
