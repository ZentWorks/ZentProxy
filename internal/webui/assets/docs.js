(() => {
  const A = (id, category, en, de) => ({id, category, en, de});
  const articles = [
    A('getting-started','Getting Started',
      {title:'Getting Started',summary:'The basic ZentProxy workflow from first login to the first proxy host.',sections:[
        ['How ZentProxy works',['You configure hosts in the WebUI. ZentProxy validates the settings and applies the configuration automatically.','The default installation stores configuration and statistics in SQLite under /data, so no separate database is required.']],
        ['First proxy host',['Create a Proxy Host, enter one or more domains or IP addresses, select http or https for the upstream, and enter the target host and port. Enable a certificate only when HTTPS should be served by ZentProxy.'],['A domain or IP can only belong to one proxy host.','Analytics can be enabled or disabled per host.','Use Trusted Proxy when traffic arrives through Cloudflare or another supported reverse proxy.']],
        ['Recommended first steps',['Create or import your proxy hosts.','Configure certificates for HTTPS hosts.','On each Proxy Host that is reached through Cloudflare, select Cloudflare as the Trusted Proxy Provider in the General tab.','Verify Analytics and then review the Audit Log after configuration changes.']]
      ]},
      {title:'Erste Schritte',summary:'Der grundlegende ZentProxy-Ablauf vom ersten Login bis zum ersten Proxy Host.',sections:[
        ['So arbeitet ZentProxy',['Du konfigurierst Hosts bequem in der WebUI. ZentProxy prüft die Einstellungen und übernimmt die Konfiguration automatisch.','Die Standardinstallation speichert Konfiguration und Statistiken in SQLite unter /data. Eine separate Datenbank ist nicht notwendig.']],
        ['Ersten Proxy Host anlegen',['Lege einen Proxy Host an, trage eine oder mehrere Domains oder IP-Adressen ein, wähle http oder https für das Ziel und gib Zielhost sowie Port an. Ein Zertifikat brauchst du nur, wenn ZentProxy selbst HTTPS bereitstellen soll.'],['Eine Domain oder IP kann nur einem Proxy Host zugeordnet sein.','Statistiken lassen sich pro Host ein- oder ausschalten.','Nutze Trusted Proxy, wenn der Traffic über Cloudflare oder einen anderen vorgeschalteten Proxy kommt.']],
        ['Empfohlene erste Schritte',['Proxy Hosts anlegen oder importieren.','Zertifikate für HTTPS-Hosts konfigurieren.','Bei jedem Proxy Host, der über Cloudflare erreicht wird, im General-Tab Cloudflare als Trusted Proxy Provider auswählen.','Statistiken prüfen und nach Änderungen das Audit-Protokoll kontrollieren.']]
      ]}),
    A('proxy-hosts','Proxy Hosts & Routing',
      {title:'Proxy Hosts & Routing',summary:'Domains, upstreams, WebSockets, custom locations and advanced OpenResty configuration.',sections:[
        ['Proxy hosts',['A proxy host maps one or more incoming domains or IP addresses to an upstream application. The upstream can use HTTP or HTTPS and may be addressed by Docker name, hostname or IP.']],
        ['WebSockets and Host header',['Enable WebSockets for applications that use connection upgrades. Preserve Host forwards the original incoming hostname instead of replacing it with the upstream hostname.']],
        ['Custom locations',['Custom locations route selected URL paths to a different upstream. They are useful when one public hostname needs to serve multiple internal services.']],
        ['Advanced configuration',['Advanced OpenResty directives are intentionally separated from the common settings. Use them only when a native ZentProxy option does not cover the requirement. Imported directives are preserved.']]
      ]},
      {title:'Proxy Hosts & Routing',summary:'Domains, Ziele, WebSockets, Custom Locations und erweiterte OpenResty-Konfiguration.',sections:[
        ['Proxy Hosts',['Ein Proxy Host ordnet eine oder mehrere eingehende Domains oder IP-Adressen einer internen Anwendung zu. Domains und IPs werden im Host-Dialog als Chips erfasst: Wert eingeben, Enter drücken, mit × oder Backspace entfernen. Die Host-Liste kann live nach Name, Domain oder Ziel gefiltert und alternativ nach Basisdomain gruppiert angezeigt werden. Das Ziel kann HTTP oder HTTPS nutzen.']],
        ['WebSockets und Host-Header',['Aktiviere WebSockets bei Anwendungen, die Connection-Upgrades verwenden. „Host beibehalten“ leitet den ursprünglich aufgerufenen Hostnamen weiter, statt ihn durch den Zielhost zu ersetzen.']],
        ['Custom Locations',['Custom Locations können bestimmte URL-Pfade an ein anderes Ziel weiterleiten. Das ist sinnvoll, wenn ein öffentlicher Hostname mehrere interne Dienste bereitstellt.']],
        ['Erweiterte Konfiguration',['Erweiterte OpenResty-Direktiven sind bewusst von den normalen Optionen getrennt. Nutze sie nur, wenn es dafür noch keine native ZentProxy-Einstellung gibt. Importierte Direktiven bleiben erhalten.']]
      ]}),
    A('certificates','SSL & Certificates',
      {title:'SSL & Certificates',summary:'TLS certificates, Force HTTPS, HTTP/2, HSTS and imported PEM material.',sections:[
        ['Certificate types',['ZentProxy supports Let’s Encrypt certificates and imported PEM certificates. A certificate consists of a certificate chain and its matching private key. The display name and description are ZentProxy metadata and can be edited without replacing the certificate.']],
        ['Host TLS settings',['Assign a certificate to a proxy host to enable HTTPS. Force HTTPS redirects plain HTTP to HTTPS. HTTP/2 can be enabled for TLS listeners.']],
        ['HSTS',['HSTS tells browsers to use HTTPS for future requests. Enable it only after HTTPS works reliably. HSTS Subdomains extends the policy to subdomains and should be used carefully.']],
        ['Imported certificates',['Custom PEM certificates are copied into ZentProxy-managed storage. ZentProxy cannot automatically renew arbitrary custom certificates unless a future provider integration explicitly supports it.']]
      ]},
      {title:'SSL & Zertifikate',summary:'TLS-Zertifikate, HTTPS erzwingen, HTTP/2, HSTS und importierte PEM-Daten.',sections:[
        ['Zertifikatstypen',['ZentProxy unterstützt Let’s-Encrypt-Zertifikate und importierte PEM-Zertifikate. Ein Zertifikat besteht aus der Zertifikatskette und dem dazugehörigen privaten Schlüssel.']],
        ['TLS-Einstellungen am Host',['Ordne einem Proxy Host ein Zertifikat zu, um HTTPS zu aktivieren. „HTTPS erzwingen“ leitet HTTP auf HTTPS um. HTTP/2 kann für TLS-Listener aktiviert werden.']],
        ['HSTS',['HSTS weist Browser an, künftig nur HTTPS zu verwenden. Aktiviere es erst, wenn HTTPS zuverlässig funktioniert. „HSTS für Subdomains“ erweitert die Regel auf Subdomains und sollte bewusst eingesetzt werden.']],
        ['Importierte Zertifikate',['Eigene PEM-Zertifikate werden in den von ZentProxy verwalteten Speicher kopiert. Beliebige Custom-Zertifikate können nicht automatisch erneuert werden, solange dafür keine passende Provider-Integration existiert.']]
      ]}),
    A('letsencrypt','Let’s Encrypt',
      {title:'Let’s Encrypt',summary:'HTTP-01, DNS-01, wildcard certificates and automatic renewal.',sections:[
        ['HTTP-01',['HTTP-01 is the simplest challenge. The public domain must resolve to ZentProxy and port 80 must be reachable from the Internet while the certificate is issued or renewed.']],
        ['DNS-01',['DNS-01 proves domain ownership through DNS records. It is required for wildcard certificates and works without exposing port 80, but ZentProxy needs valid API credentials for the DNS provider.']],
        ['Automatic renewal',['Managed Let’s Encrypt certificates are renewed automatically before expiry. A failed renewal is stored as certificate status information so it can be diagnosed in the WebUI.']],
        ['Migration fallback',['If an existing Let’s Encrypt certificate cannot be copied during migration but its ACME configuration is usable, ZentProxy can reissue the certificate automatically.']]
      ]},
      {title:'Let’s Encrypt',summary:'HTTP-01, DNS-01, Wildcard-Zertifikate und automatische Erneuerung.',sections:[
        ['HTTP-01',['HTTP-01 ist die einfachste Challenge. Die öffentliche Domain muss auf ZentProxy zeigen und Port 80 muss während Ausstellung oder Erneuerung aus dem Internet erreichbar sein.']],
        ['DNS-01',['DNS-01 weist den Domainbesitz über DNS-Einträge nach. Sie ist für Wildcard-Zertifikate notwendig und funktioniert ohne offenen Port 80, benötigt aber gültige API-Zugangsdaten des DNS-Providers.']],
        ['Automatische Erneuerung',['Von ZentProxy verwaltete Let’s-Encrypt-Zertifikate werden automatisch vor Ablauf erneuert. Fehler bei der Erneuerung werden am Zertifikat gespeichert und können in der WebUI nachvollzogen werden.']],
        ['Fallback bei Migration',['Kann ein vorhandenes Let’s-Encrypt-Zertifikat bei der Migration nicht kopiert werden, die ACME-Konfiguration ist aber verwendbar, kann ZentProxy das Zertifikat automatisch neu ausstellen.']]
      ]}),
    A('analytics','Analytics',
      {title:'Analytics',summary:'Per-host statistics, request details, retention and privacy-related options.',sections:[
        ['Per-host analytics',['Analytics is controlled per proxy host. Disabled hosts are still proxied normally but their requests are not stored in the analytics database.']],
        ['Stored request data',['Statistics include host, canonical client IP, path, method, status, traffic and timing data. Query strings are a separate option because URLs may contain tokens or other sensitive information.']],
        ['Views and filtering',['Use the range selector for 1h, 24h, 7d or 30d. Filter by an exact domain, click a Top Domain to drill into it, and use the visible Auto Refresh switch to control live updates.']],
        ['Real client IP',['When a CDN or reverse proxy is in front of ZentProxy, select a Trusted Proxy Provider on that Proxy Host. Otherwise statistics, rate decisions and ZentLoop may see the proxy IP instead of the real visitor.']],
        ['Retention',['Raw request retention is intentionally finite. Aggregated statistics can be kept longer in future versions without retaining every individual request indefinitely.']]
      ]},
      {title:'Statistiken',summary:'Statistiken pro Host, Request-Details, Aufbewahrung und Datenschutzoptionen.',sections:[
        ['Statistiken pro Host',['Statistiken werden pro Proxy Host gesteuert. Bei deaktivierten Statistiken wird der Host normal weitergeleitet, seine Requests werden aber nicht in der Analytics-Datenbank gespeichert.']],
        ['Gespeicherte Request-Daten',['Erfasst werden unter anderem Host, kanonische Client-IP, Pfad, Methode, Statuscode, Traffic und Laufzeiten. Query-Strings sind eine separate Option, weil URLs Tokens oder andere sensible Informationen enthalten können.']],
        ['Ansichten und Filter',['Über den Zeitraum-Schalter wählst du 1h, 24h, 7d oder 30d. Du kannst nach einer exakten Domain filtern, eine Top-Domain direkt anklicken und die sichtbare Auto-Aktualisierung ein- oder ausschalten.']],
        ['Echte Client-IP',['Wenn vor ZentProxy ein CDN oder weiterer Reverse Proxy steht, konfiguriere einen Trusted-Proxy-Provider. Sonst sehen Statistiken, Sicherheitsentscheidungen und ZentLoop möglicherweise nur die Proxy-IP statt des echten Besuchers.']],
        ['Aufbewahrung',['Raw Requests werden bewusst nur begrenzt aufbewahrt. Aggregierte Statistiken können später länger erhalten bleiben, ohne jeden einzelnen Request unbegrenzt zu speichern.']]
      ]}),
    A('trusted-proxies','Trusted Proxies & Cloudflare',
      {title:'Trusted Proxies & Cloudflare',summary:'Restore real client IPs safely when traffic arrives through Cloudflare or another proxy.',sections:[
        ['Why trusted proxies matter',['A reverse proxy or CDN connects to ZentProxy on behalf of the visitor. Without trusted-proxy handling, the apparent client IP is the proxy address.']],
        ['Cloudflare',['Select Cloudflare for hosts that are proxied through Cloudflare. ZentProxy uses CF-Connecting-IP as the canonical client address only for hosts that explicitly select the Cloudflare provider.']],
        ['Direct traffic on Docker Desktop',['With Direct / None, ZentProxy does not trust forwarded client-IP headers. Docker Desktop for macOS can replace the original source address before the connection reaches the container, commonly exposing a gateway address such as 192.168.65.1. In that case the original visitor IP is no longer available to ZentProxy, so Analytics and forwarded X-Real-IP/X-Forwarded-For values may show that gateway address. ZentProxy does not guess or trust arbitrary headers to work around this.']],
        ['Do not trust everyone',['Never accept forwarded client-IP headers from arbitrary Internet addresses. Attackers can forge those headers unless the sender is verified as a trusted proxy.']]
      ]},
      {title:'Trusted Proxies & Cloudflare',summary:'Echte Client-IPs sicher wiederherstellen, wenn Traffic über Cloudflare oder einen anderen Proxy kommt.',sections:[
        ['Warum Trusted Proxies wichtig sind',['Ein Reverse Proxy oder CDN verbindet sich stellvertretend für den Besucher mit ZentProxy. Ohne Trusted-Proxy-Behandlung erscheint deshalb die Proxy-Adresse als Client-IP.']],
        ['Cloudflare',['Wähle Cloudflare bei Hosts, die über Cloudflare proxied werden. ZentProxy verwendet CF-Connecting-IP nur bei Hosts mit ausdrücklich ausgewähltem Cloudflare-Provider als kanonische Client-IP.']],
        ['Direkter Traffic unter Docker Desktop',['Bei Direct / None vertraut ZentProxy keinen weitergereichten Client-IP-Headern. Docker Desktop für macOS kann die ursprüngliche Quelladresse bereits vor dem Container ersetzen; häufig sieht ZentProxy dann nur eine Gateway-IP wie 192.168.65.1. In diesem Fall steht ZentProxy die ursprüngliche Besucher-IP nicht mehr zur Verfügung. Statistiken sowie X-Real-IP/X-Forwarded-For können deshalb diese Gateway-IP enthalten. ZentProxy versucht nicht, die Adresse zu erraten oder dafür beliebige Header zu vertrauen.']],
        ['Nicht jedem Header vertrauen',['Forwarded-IP-Header dürfen niemals von beliebigen Internet-Adressen akzeptiert werden. Angreifer können solche Header fälschen, wenn der Absender nicht als vertrauenswürdiger Proxy geprüft wird.']]
      ]}),
    A('access-routing','Access Lists & Streams',
      {title:'Access Lists & Streams',summary:'Allow/deny rules, Basic Auth, redirects, 404 hosts and TCP/UDP streams.',sections:[
        ['Access lists',['Access lists combine separate IP/CIDR allow and deny lists with optional username/password protection. You can use IP rules only, login credentials only, require both, or allow either one to grant access. Credentials are managed directly in ZentProxy and stored as bcrypt htpasswd hashes. Assign a list to proxy hosts that should not be publicly accessible without restrictions.']],
        ['Redirect and 404 hosts',['Redirect hosts send incoming requests to another URL. 404 hosts intentionally terminate matching hostnames without forwarding to an application.']],
        ['Routing management',['Redirect hosts, explicit 404 hosts and TCP/UDP streams are managed on the Routing page. Click an existing row to edit it or use the add action in each section.']],
        ['Streams',['Streams proxy raw TCP and/or UDP traffic. The incoming port must also be published by Docker or Unraid; ZentProxy cannot add a new host port mapping to an already running container.']]
      ]},
      {title:'Zugriffslisten & Streams',summary:'Allow/Deny-Regeln, Basic Auth, Weiterleitungen, 404-Hosts und TCP/UDP-Streams.',sections:[
        ['Zugriffslisten',['Zugriffslisten kombinieren getrennte Allow- und Deny-Listen für IPs/CIDR-Netze mit optionalem Benutzername/Passwort-Schutz. Du kannst nur IP-Regeln, nur Zugangsdaten, beides verpflichtend oder wahlweise eines von beiden verwenden. Zugangsdaten werden direkt in ZentProxy verwaltet und als bcrypt-htpasswd-Hashes gespeichert.']],
        ['Redirect- und 404-Hosts',['Redirect Hosts leiten eingehende Anfragen auf eine andere URL weiter. 404-Hosts beenden passende Hostnamen bewusst, ohne sie an eine Anwendung weiterzuleiten.']],
        ['Routing-Verwaltung',['Weiterleitungen, explizite 404-Hosts und TCP/UDP-Streams werden auf der Seite Routing verwaltet. Bestehende Einträge kannst du anklicken und bearbeiten oder über die jeweilige Hinzufügen-Aktion neue Einträge erstellen.']],
        ['Streams',['Streams leiten rohen TCP- und/oder UDP-Traffic weiter. Der eingehende Port muss zusätzlich in Docker oder Unraid veröffentlicht werden; ZentProxy kann einem bereits laufenden Container nicht selbst nachträglich ein Host-Port-Mapping hinzufügen.']]
      ]}),
    A('migration','Migration',
      {title:'Migration',summary:'Analyze a running source installation and transfer supported configuration safely.',sections:[
        ['Analyze first',['Migration analysis is read-only. ZentProxy inspects hosts, certificates, access lists, redirects, 404 hosts and streams before writing anything locally.']],
        ['Full migration',['A full migration imports compatible routing, access and TLS settings. Managed Let’s Encrypt certificates may be reissued when safe. If a Let’s Encrypt reissue fails during the import, ZentProxy continues with the remaining migration and leaves dependent routing objects without TLS until the certificate is successfully issued and attached.']],
        ['Blocking conditions',['ZentProxy blocks the full migration when continuing would create a broken setup, for example when a DNS-01 certificate needs credentials that cannot be preserved safely.']],
        ['Source remains unchanged',['The migration source is never modified. Keep the old proxy available until imported hosts and certificates have been tested on ZentProxy.']]
      ]},
      {title:'Migration',summary:'Eine laufende Quellinstallation analysieren und unterstützte Konfiguration sicher übernehmen.',sections:[
        ['Erst analysieren',['Die Migrationsanalyse arbeitet read-only. ZentProxy prüft Hosts, Zertifikate, Zugriffslisten, Weiterleitungen, 404-Hosts und Streams, bevor lokal etwas geschrieben wird.']],
        ['Vollständige Migration',['Eine vollständige Migration übernimmt kompatible Routing-, Zugriffs- und TLS-Einstellungen. Verwaltete Let’s-Encrypt-Zertifikate können bei Bedarf sicher neu ausgestellt werden.']],
        ['Wann blockiert wird',['ZentProxy blockiert die vollständige Migration, wenn ein Weiterlaufen zu einem kaputten Setup führen würde, zum Beispiel bei DNS-01-Zertifikaten, deren Provider-Zugangsdaten nicht sicher übernommen werden können.']],
        ['Quelle bleibt unverändert',['Die Quellinstallation wird nicht verändert. Lass den alten Proxy verfügbar, bis importierte Hosts und Zertifikate in ZentProxy getestet wurden.']]
      ]}),
    A('zentloop','ZentLoop Integration',
      {title:'ZentLoop Integration',summary:'Connect ZentProxy to ZentLoop for catch-all and deception workflows.',sections:[
        ['Purpose',['ZentLoop is integrated through a proxy-neutral protocol instead of being compiled into the proxy core. This keeps both projects independently usable.']],
        ['Catch-all routing',['ZentProxy automatically derives known root domains from configured Proxy Hosts. Unconfigured subdomains inside those domains can use the ZentLoop catch-all. Hostnames outside all known root domains reach ZentLoop only when the Unknown/Fake Hosts toggle is enabled.']],
        ['Signed ingress',['An optional shared secret signs integration metadata with HMAC-SHA256. ZentProxy also performs a signed integration check so a wrong or outdated secret is visible as a mismatch before traffic depends on it.']],
        ['Health and fallback',['ZentProxy checks ZentLoop every 15 seconds and shows reachability, signature state, latency and errors. If the integration is unavailable or a configured signature cannot be verified, routing fails closed with the selected 403 or 503 fallback instead of hanging.']]
      ]},
      {title:'ZentLoop-Integration',summary:'ZentProxy mit ZentLoop für Catch-All- und Deception-Abläufe verbinden.',sections:[
        ['Zweck',['ZentLoop wird über ein proxy-neutrales Protokoll angebunden und nicht fest in den Proxy-Kern kompiliert. So bleiben beide Projekte unabhängig nutzbar.']],
        ['Catch-All-Routing',['ZentProxy leitet bekannte Root-Domains automatisch aus den konfigurierten Proxy Hosts ab. Nicht konfigurierte Subdomains innerhalb dieser Domains können den ZentLoop-Catch-All verwenden. Hostnamen außerhalb aller bekannten Root-Domains erreichen ZentLoop nur, wenn der Schalter für Unknown/Fake Hosts aktiviert ist.']],
        ['Signierter Ingress',['Ein optionales gemeinsames Secret signiert Integrationsmetadaten per HMAC-SHA256. ZentProxy führt zusätzlich eine signierte Integrationsprüfung durch, damit ein falsches oder veraltetes Secret vor dem Routing als Fehler sichtbar wird.']],
        ['Health und Fallback',['ZentProxy prüft ZentLoop alle 15 Sekunden und zeigt Erreichbarkeit, Signaturstatus, Latenz und Fehler. Ist die Integration nicht verfügbar oder kann eine konfigurierte Signatur nicht verifiziert werden, greift der gewählte 403- oder 503-Fallback statt den Request hängen zu lassen.']]
      ]}),
    A('developer-api','Developer API & Integrations',
      {title:'Developer API & Integrations',summary:'Versioned REST API and scoped API keys for integrations.',sections:[
        ['API first',['The ZentProxy WebUI uses the same versioned backend API that is available to integrations. The stable base path is /api/v1.']],
        ['API keys',['Create separate API keys for integrations and grant only the scopes they need. API keys are revocable and cannot create additional API keys.']]
      ]},
      {title:'Entwickler-API & Integrationen',summary:'Versionierte REST-API und API-Schlüssel mit Scopes für Integrationen.',sections:[
        ['API first',['Die ZentProxy-WebUI verwendet dieselbe versionierte Backend-API, die auch Integrationen zur Verfügung steht. Der stabile Basispfad ist /api/v1.']],
        ['API-Schlüssel',['Erstelle für Integrationen getrennte API-Schlüssel und gib ihnen nur die benötigten Scopes. API-Schlüssel sind widerrufbar und können selbst keine weiteren API-Schlüssel erstellen.']]
      ]}),
    A('troubleshooting','Troubleshooting',
      {title:'Troubleshooting',summary:'Common checks when a host, certificate or migration does not behave as expected.',sections:[
        ['Host does not respond',['Verify that the public DNS points to ZentProxy, that Docker/Unraid publishes the expected HTTP/HTTPS ports, and that the upstream host and port are reachable from inside the ZentProxy container.']],
        ['Let’s Encrypt fails',['For HTTP-01, verify public port 80 and DNS resolution. For DNS-01, verify the provider name and credentials. Check the certificate status for the latest ACME error.']],
        ['Wrong client IP',['If a host is behind Cloudflare, configure Cloudflare as its Trusted Proxy Provider. With Direct / None on Docker Desktop for macOS, a gateway address such as 192.168.65.1 can be expected because Docker may hide the original source IP before ZentProxy receives the connection.']],
        ['Migration warning',['Orange migration messages are warnings or planned fallbacks. Red blocking messages mean ZentProxy cannot guarantee a working result and therefore refuses the full import until the dependency is resolved.']]
      ]},
      {title:'Fehlerbehebung',summary:'Typische Prüfungen, wenn Host, Zertifikat oder Migration nicht wie erwartet funktionieren.',sections:[
        ['Host antwortet nicht',['Prüfe, ob das öffentliche DNS auf ZentProxy zeigt, ob Docker/Unraid die erwarteten HTTP-/HTTPS-Ports veröffentlicht und ob Zielhost sowie Zielport aus dem ZentProxy-Container erreichbar sind.']],
        ['Let’s Encrypt schlägt fehl',['Bei HTTP-01 müssen öffentlicher Port 80 und DNS-Auflösung stimmen. Bei DNS-01 prüfe Provider und Zugangsdaten. Am Zertifikat findest du den letzten ACME-Fehler.']],
        ['Falsche Client-IP',['Liegt ein Host hinter Cloudflare, wähle an diesem Proxy Host Cloudflare als Trusted-Proxy-Provider. Bei Direct / None unter Docker Desktop für macOS kann dagegen eine Gateway-IP wie 192.168.65.1 normal sein, weil Docker die ursprüngliche Quell-IP bereits vor ZentProxy verbergen kann.']],
        ['Migrationswarnung',['Orange Hinweise sind Warnungen oder geplante Fallbacks. Rote Blocker bedeuten, dass ZentProxy kein funktionierendes Ergebnis garantieren kann und deshalb den Full Import stoppt, bis die Abhängigkeit behoben ist.']]
      ]})
  ];
  window.ZentDocs = { articles, get(id,lang){const a=articles.find(x=>x.id===id); return a ? {...a,...(a[lang]||a.en)} : null;} };
})();
