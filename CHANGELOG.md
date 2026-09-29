# Changelog – IK Site Security

## 2.4.0 (29.09.2026)
Sikkerhetsretting etter security review av 2.3.3.
- Lockout stopper nå innlogging, også med riktig passord (sjekken kjører etter WordPress sin passordsjekk).
- IP leses bare fra REMOTE_ADDR. CF-Connecting-IP og X-Forwarded-For kan forfalskes og brukes ikke lenger.
- Feilforsøk telles bare innenfor lockout-tiden. Gamle rader ryddes, tabellen holdes under 1000 rader.
- Et nytt forsøk under aktiv lockout forlenger ikke ventetiden.
- Unntaket for /wp-admin/options.php er fjernet (utloggede får 404).
- Brukerlisten i REST API (/wp-json/wp/v2/users) er skjult for utloggede når author-blokkering er på.
- Grenser ved lagring: forsøk 2-20, lockout 5-1440 minutter. Tom eller reservert login-slug gir «portal».
- User-Agent kortes ned til 255 tegn før lagring i innloggingsloggen.
- Admin-teksten sier nå 404, slik koden faktisk gjør.
- Fjernet ubrukt kode: modules/login.php, login/login-template.php, login/login.css.
- Ny uninstall.php: sletter tabeller, ikss_-innstillinger og .htaccess-blokken ved sletting.
- .htaccess-reglene virker nå på både Apache 2.4 og 2.2.
- Ny oppgraderingsrutine: .htaccess og tabeller oppdateres automatisk etter oppdatering.
- ?ikss_debug=1 viser hvilken IP serveren ser.

## Etter 1.7.0, til og med 2.3.3
Ikke dokumentert. Laget utenfor git, finnes bare som release-zip på GitHub.


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
