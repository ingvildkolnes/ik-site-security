<?php defined( 'ABSPATH' ) || exit;
$site_name = get_bloginfo( 'name' );
$logo_url  = get_site_icon_url( 80 );
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo( 'charset' ); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php echo esc_html( $site_name ); ?> — Innlogging</title>
    <meta name="robots" content="noindex, nofollow">
    <?php wp_head(); ?>
</head>
<body class="ikss-login-body">
<div class="ikss-login-bg">
    <div class="ikss-login-card">

        <div class="ikss-login-header">
            <?php if ( $logo_url ) : ?>
                <img src="<?php echo esc_url( $logo_url ); ?>" alt="Logo" class="ikss-logo">
            <?php else : ?>
                <div class="ikss-logo-placeholder">🔒</div>
            <?php endif; ?>
            <h1 class="ikss-site-name"><?php echo esc_html( $site_name ); ?></h1>
            <p class="ikss-tagline">Logg inn for å fortsette</p>
        </div>

        <?php if ( $error ) : ?>
            <div class="ikss-error" role="alert">
                <span class="ikss-error-icon">⚠</span>
                <?php echo esc_html( $error ); ?>
            </div>
        <?php endif; ?>

        <form method="post" class="ikss-form" novalidate>
            <?php wp_nonce_field( 'ikss_login', 'ikss_nonce' ); ?>

            <div class="ikss-field">
                <label for="log" class="ikss-label">Brukernavn eller e-post</label>
                <input type="text" id="log" name="log" class="ikss-input"
                    autocomplete="username" autofocus required
                    value="<?php echo esc_attr( $_POST['log'] ?? '' ); ?>" />
            </div>

            <div class="ikss-field">
                <label for="pwd" class="ikss-label">Passord</label>
                <div class="ikss-password-wrap">
                    <input type="password" id="pwd" name="pwd" class="ikss-input"
                        autocomplete="current-password" required />
                    <button type="button" class="ikss-toggle-pw" aria-label="Vis passord" tabindex="-1">👁</button>
                </div>
            </div>

            <label class="ikss-remember">
                <input type="checkbox" name="rememberme" value="forever">
                <span>Husk meg</span>
            </label>

            <button type="submit" class="ikss-btn">Logg inn</button>
        </form>

        <div class="ikss-footer-links">
            <a href="<?php echo esc_url( wp_lostpassword_url() ); ?>">Glemt passord?</a>
        </div>

    </div>
</div>
<script>
document.querySelector('.ikss-toggle-pw')?.addEventListener('click', function() {
    const input = document.getElementById('pwd');
    input.type = input.type === 'password' ? 'text' : 'password';
    this.textContent = input.type === 'password' ? '👁' : '🙈';
});
</script>
<?php wp_footer(); ?>
</body>
</html>
