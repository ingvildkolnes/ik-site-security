# Changelog – IK Site Security

## 2.5.0 (26.10.2026)
Alle funn fra gjennomgangen av 2.4.0, pluss alt som sto i Notion-feltet «Til neste oppdatering».
- IP bak Cloudflare: CF-Connecting-IP brukes bare når REMOTE_ADDR er en Cloudflare-adresse (fast liste over Cloudflares IP-områder i koden). Ellers REMOTE_ADDR. Ingen innstilling, virker likt på alle sider. Debug-visningen (?ikss_debug=1) sier hvilken kilde som ble brukt.
- Lockout-tabellen bruker UTC. Sommertid/vintertid påvirker ikke lenger lockout-tiden. Gamle rader tømmes ved oppgradering. Admin viser lokal tid.
- Feil app-passord mot REST API telles som innloggingsforsøk, og låst IP får 401 på REST-kall med Basic Auth.
- Oppgraderingsrutinen har lås mot samtidige kjøringer.
- Bryteren «E-postvarsel ved innlogging fra ny IP» ligger nå inne i lagre-skjemaet (kunne ikke lagres før).
- Ny modul: Tving HTTPS. 301 fra http til https og Strict-Transport-Security (max-age ett døgn). Slår seg bare på når pluginens egen SSL-selvsjekk lykkes og WordPress-adressen er https. Selvsjekken kjøres i bakgrunnen (wp-cron) én gang i døgnet og rett etter oppgradering, så ingen besøkende venter på den. Ved aktivering og lagring av innstillinger kjøres den med en gang. Feiler den, vises melding i wp-admin og tvangen holdes av på den siden.
- Ny modul: security.txt (RFC 9116) på /.well-known/security.txt, servert virtuelt uten fil i rotmappa. Expires fornyer seg selv. Kontakt-e-post i innstillingene, ellers admin-e-post.
- Ny modul: REST-feillogg. Alle REST-svar med 401/403 logges (tid, IP, rute, status) i egen tabell, maks 500 rader, vises i admin. Opprydding kjøres i snitt hver 20. gang, ikke ved hver rad.
- Ny modul: statusendepunkt GET /wp-json/ikss/v1/status (åpent, uten hemmeligheter): versjon, custom login på/av, aktive lockouts, HTTPS-status, SSL-selvsjekk, security.txt, REST-feil siste døgn.
- SEOPress-overlapp vurdert: pluginen og SEOPress kan begge fjerne generator-tag, RSD og WLW. Pluginen gjør det uansett, SEOPress bare når det er skrudd på. Ingen endring. XML-RPC-blokkeringen er ikke det samme som SEOPress sin X-Pingback-fjerning.
- Overskriftene i admin bruker kolon i stedet for tankestrek.

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
