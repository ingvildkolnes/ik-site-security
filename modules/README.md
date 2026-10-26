# modules

Sist oppdatert: 26.10.2026

Funksjonsmodulene i ik-site-security. Hver fil er ett avgrenset ansvar.

- `admin.php` - innstillingssiden i wp-admin
- `brute-force.php` - sperre mot gjentatte innloggingsforsøk, IP-oppslag (Cloudflare-bevisst) og UTC-tidsfunksjoner
- `https.php` - tving HTTPS med SSL-selvsjekk og HSTS (2.5.0)
- `login-log.php` - logging av innlogginger
- `redirects.php` - omdirigeringer etter innlogging
- `rest-log.php` - logg over avviste REST-kall, 401/403 (2.5.0)
- `security-txt.php` - virtuell /.well-known/security.txt (2.5.0)
- `security.php` - generelle sikkerhetstiltak
- `status.php` - åpent statusendepunkt /wp-json/ikss/v1/status (2.5.0)
- `updater.php` - oppdatering av pluginet fra GitHub

## Endringslogg

- 04.10.2026 - README opprettet
- 26.10.2026 - fire nye moduler fra 2.5.0 ført opp
