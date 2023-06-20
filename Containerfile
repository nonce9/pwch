FROM docker.io/debian:latest

# install dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git \
    golang \
    sudo \
    curl \
    supervisor \
    postgresql \
    postfix \
    postfix-pgsql \
    dovecot-imapd \
    dovecot-lmtpd \
    dovecot-pgsql \
    && apt-get clean

# copy postgres config files and database sql script
COPY test/postgres/postgres.conf /etc/postgresql/15/main/conf.d/custom.conf
COPY test/postgres/pg_hba.conf /etc/postgresql/15/main
COPY test/postgres/postgres.sql /root

# prepare database
RUN pg_ctlcluster 15/main start \
    && sudo -u postgres psql -c "CREATE USER vmail with password 'password';" \
    && sudo -u postgres psql -c "CREATE DATABASE vmail;" \
    && sudo -u postgres psql -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;" vmail \
    && sudo -u postgres psql vmail < /root/postgres.sql

# generate certificate
RUN openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout /etc/ssl/localhost.key -out /etc/ssl/localhost.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost" \
    -addext "subjectAltName = DNS:localhost" \
    && cp /etc/ssl/localhost.crt /usr/local/share/ca-certificates/localhost.crt \
    && update-ca-certificates

# configure postfix
COPY test/postfix/main.cf /root/main.cf

RUN cat /root/main.cf >> /etc/postfix/main.cf \
    && sed -i 's/smtpd_tls_cert_file=.*/smtpd_tls_cert_file=\/etc\/ssl\/localhost.crt/' /etc/postfix/main.cf \
    && sed -i 's/smtpd_tls_key_file=.*/smtpd_tls_key_file=\/etc\/ssl\/localhost.key/' /etc/postfix/main.cf \
    && mkdir /etc/postfix/sql

COPY test/postfix/master.cf /etc/postfix
COPY test/postfix/accounts.cf /etc/postfix/sql
COPY test/postfix/aliases.cf /etc/postfix/sql
COPY test/postfix/domains.cf /etc/postfix/sql
COPY test/postfix/sender-login-maps.cf /etc/postfix/sql

# configure dovecot
RUN groupadd -g 5000 vmail \
    && useradd -c "vmail user" -s /usr/sbin/nologin -d /var/vmail -u 5000 -g vmail -m -r vmail \
    && mkdir -p /var/vmail/mailboxes \
    && chown -R vmail:vmail /var/vmail \
    && chmod -R 0770 /var/vmail \
    && rm -rf /etc/dovecot/conf.d /etc/dovecot/dovecot-dict-auth.conf.ext /etc/dovecot/dovecot-dict-sql.conf.ext /etc/dovecot/dovecot-sql.conf.ext

COPY --chown=root:dovecot --chmod=0640 test/dovecot/dovecot.conf /etc/dovecot
COPY --chown=root:dovecot --chmod=0440 test/dovecot/dovecot-sql.conf /etc/dovecot

# encrypt mailboxes
ARG PASSWORD=e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716

RUN pg_ctlcluster 15/main start \
    && /usr/sbin/dovecot -c /etc/dovecot/dovecot.conf \
    && /bin/doveadm -o plugin/mail_crypt_private_password=$PASSWORD mailbox cryptokey generate -u pwch1@localdomain -U \
    && /bin/doveadm -o plugin/mail_crypt_private_password=$PASSWORD mailbox cryptokey generate -u pwch2@localdomain -U \
    && /bin/doveadm -o plugin/mail_crypt_private_password=$PASSWORD mailbox cryptokey generate -u pwch3@localdomain -U

# install pwch
RUN mkdir /etc/pwch /usr/local/src/pwch

COPY config/config.yml /etc/pwch/config.yml
ADD assets/html/ /usr/local/src/pwch/

# symlink doveadm_wrapper
RUN ln -s /pwch/cmd/doveadm_wrapper/doveadm_wrapper /usr/local/bin/doveadm_wrapper

# copy supervisord config
COPY test/supervisord/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
