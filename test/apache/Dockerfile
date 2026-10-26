ARG BASE=debian:trixie
FROM ${BASE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apache2 lua-socket \
 && rm -rf /var/lib/apt/lists/* \
 && a2enmod lua \
 && ln -sf /dev/stderr /var/log/apache2/error.log
COPY lua/crowdsec-apache-bouncer.lua /usr/share/crowdsec-apache-bouncer/crowdsec-apache-bouncer.lua
COPY apache/crowdsec-apache-bouncer.conf /etc/apache2/conf-available/crowdsec-apache-bouncer.conf
COPY test/apache/echo.lua /usr/share/crowdsec-apache-bouncer-test/echo.lua
COPY test/apache/test-site.conf /etc/apache2/conf-available/test-site.conf
RUN a2enconf crowdsec-apache-bouncer test-site
CMD ["apache2ctl", "-D", "FOREGROUND"]
