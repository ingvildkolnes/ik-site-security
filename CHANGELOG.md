# Changelog – IK Site Security

## 1.7.0
- Lagt til støtte for automatiske oppdateringer via GitHub (Plugin Update Checker)

## 1.6.0
- Lagt til innloggingslogg (vises i admin)
- E-postvarsel ved innlogging fra ny IP-adresse

## 1.5.0
- Brute force-beskyttelse lagt tilbake
- Fikset at lockout-melding ikke vistes på login-siden
- Fikset konflikt mellom hide_login_errors og brute force-melding

## 1.4.0
- Komplett omskriving av login/redirect-modul
- Bruker nå samme teknikk som WPS Hide Login (plugins_loaded + wp_loaded)
- /wp-admin gir nå korrekt 404 for ikke-innloggede

## 1.3.0
- Første forsøk på å bruke setup_theme for tidlig intercept
- /wp-login.php og /wp-admin gir 404

## 1.2.0
- Fikset at /wp-admin redirectet til /portal i stedet for å gi 404
- Versjonsnummer oppdatert korrekt

## 1.1.0
- XML-RPC blokkert på servernivå via .htaccess (ikke bare WP-filter)
- Beskyttelse av wp-config.php, .htaccess og readme/lisensfiler
- Brute force-beskyttelse med lockout-liste i admin
- Author-scanning (?author=1) blokkert
- Custom login-side på valgfri slug (standard: /portal)
- Redirects fra wp-login.php og wp-admin
- Sikkerhetstoppfiler (X-Content-Type, X-Frame-Options osv.)

## 1.0.0
- Første versjon
- XML-RPC deaktivert via WP-filter
- WP-versjon fjernet fra head og RSS
- RSD og WLW manifest-lenker fjernet
- Deaktiver filredigering i admin
- Skjul innloggingsfeil
- Sikkerhetstoppfiler
