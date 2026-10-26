# crowdsec-apache-bouncer

A [CrowdSec](https://crowdsec.net) **AppSec (WAF) remediation component for Apache httpd**, written in Lua for the
stock `mod_lua` module. No compilation, no extra Apache module: a Lua script, a configuration file and two Apache
directives.

Every request is submitted to a CrowdSec [AppSec component](https://docs.crowdsec.net/docs/appsec/intro) before Apache
serves it. When CrowdSec matches a virtual patch or a generic rule, the request is answered with `403 Forbidden` and
CrowdSec raises an alert (and, through its scenarios, a ban that your firewall bouncers can enforce).

```
client ──► Apache ──(access checker, mod_lua)──► CrowdSec AppSec :7422
             │                                       │
             │◄──────── 200 allow / 403 ban ─────────┘
             ▼
        content handler (static files, PHP, proxy, CGI…)
```

## Features

- In-band blocking with the CrowdSec AppSec rules (virtual patching, generic rules, CRS).
- Fail-open by default: if CrowdSec is unreachable, slow or rejects the API key, requests go through
  (`APPSEC_FAILURE_ACTION=deny` to fail closed). Failures are logged at most once a minute per thread.
- Bounded latency: a configurable timeout on every network operation (500 ms by default).
- Location exclusions (health checks, status pages…).
- Plain Lua 5.1 to 5.4 code, tested on Debian 13 (Apache 2.4.69, Lua 5.4) and Ubuntu 22.04 (Apache 2.4.52, Lua 5.3).

## Limitations

- **The request body is not inspected.** In an access checker, `mod_lua` can only read the body by consuming it, and
  the content handler would then receive an empty body. Rules on headers, URI, query string, method and client IP
  apply; rules that look at POST bodies do not.
- No LAPI decision check: this component only asks the AppSec component. Enforce LAPI bans with a firewall bouncer
  (`crowdsec-firewall-bouncer`), which is the most efficient place to drop banned IPs anyway.
- No captcha remediation: a `captcha` action from AppSec is answered like a ban.
- One HTTP connection to the AppSec component per request (LuaSocket has no keep-alive). Expect around 1 ms of
  extra latency per request with a local AppSec component.

## Requirements

- Apache httpd 2.4 with `mod_lua` (`a2enmod lua` on Debian/Ubuntu).
- [LuaSocket](https://lunarmodules.github.io/luasocket/) for the Lua version `mod_lua` is linked against
  (`apt install lua-socket` ships it for Lua 5.1 to 5.4).
- A CrowdSec agent (1.6 or later) with an AppSec acquisition, for instance `/etc/crowdsec/acquis.d/appsec.yaml`:

  ```yaml
  source: appsec
  listen_addr: 127.0.0.1:7422
  path: /
  appsec_configs:
    - crowdsecurity/appsec-default
  labels:
    type: appsec
  ```

  with the rules: `cscli collections install crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules`.

## Installation

```sh
apt install lua-socket
install -D -m 0644 lua/crowdsec-apache-bouncer.lua /usr/share/crowdsec-apache-bouncer/crowdsec-apache-bouncer.lua
install -D -m 0640 -g www-data config/crowdsec-apache-bouncer.conf /etc/crowdsec/bouncers/crowdsec-apache-bouncer.conf
install -m 0644 apache/crowdsec-apache-bouncer.conf /etc/apache2/conf-available/

# API key, written to API_KEY= in the configuration file
cscli bouncers add apache-$(hostname)

a2enmod lua
a2enconf crowdsec-apache-bouncer
apache2ctl configtest && systemctl reload apache2
```

The configuration file must be readable by the Apache worker user (`www-data`), and should not be readable by others
since it holds the API key.

Check it: `curl -i http://your-site/.env` should now answer `403` and Apache's error log should show
`crowdsec: blocked GET /.env from …`.

## Configuration

`/etc/crowdsec/bouncers/crowdsec-apache-bouncer.conf` (another path can be given with the
`CROWDSEC_APACHE_BOUNCER_CONFIG` environment variable, e.g. in `/etc/apache2/envvars`). It is re-read every 60 seconds,
no reload needed.

| Key | Default | Meaning |
|---|---|---|
| `ENABLED` | `true` | `false` lets every request through without asking CrowdSec. |
| `APPSEC_URL` | `http://127.0.0.1:7422/` | URL of the AppSec component. |
| `API_KEY` | *(required)* | Bouncer API key (`cscli bouncers add`). The bouncer is disabled while it is empty. |
| `APPSEC_TIMEOUT_MS` | `500` | Timeout of each network operation (connect, send, receive). |
| `APPSEC_FAILURE_ACTION` | `passthrough` | `passthrough` or `deny` when the check fails. |
| `BLOCK_STATUS` | *(from CrowdSec, 403)* | Force the HTTP status of blocked requests. |
| `EXCLUDE_LOCATION` | *(none)* | Comma-separated URI prefixes never sent to CrowdSec. |

`apache/crowdsec-apache-bouncer.conf` enables the check server-wide. The `LuaHookAccessChecker` directive can instead be
placed in a single `<VirtualHost>`, `<Location>` or `<Directory>`.

### Behind a reverse proxy

The client address sent to CrowdSec is Apache's `useragent_ip`. Behind a load balancer or CDN, enable
[`mod_remoteip`](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html) (`RemoteIPHeader` / `RemoteIPTrustedProxy`
or `RemoteIPProxyProtocol`) so that it is the real client address, otherwise CrowdSec would ban your proxy.

## How it works

For each initial request (internal redirects and subrequests are skipped), the script sends a `GET` to the AppSec
component with the original request headers and the `X-Crowdsec-Appsec-Ip`, `-Uri`, `-Host`, `-Verb`, `-User-Agent`,
`-Http-Version` and `-Api-Key` headers, as described in the
[AppSec protocol](https://docs.crowdsec.net/docs/appsec/protocol). A `200` lets Apache go on (`DECLINED`); a `403`
returns its `http_status` (403); anything else is a failure handled according to `APPSEC_FAILURE_ACTION`.

## Tests

`test/run-tests.sh` builds Apache on Debian 13 and Ubuntu 22.04 next to a CrowdSec AppSec container (Docker Compose)
and checks: clean requests pass, `/.env` and a virtual patch (CVE-2017-9841) are blocked, excluded locations are not
checked, POST bodies still reach the content handler, and requests go through when the API key is wrong or the AppSec
component is unreachable.

```sh
./test/run-tests.sh          # KEEP=1 to leave the containers running
```

## License

MIT, see [LICENSE](LICENSE).
