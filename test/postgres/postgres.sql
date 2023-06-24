CREATE SEQUENCE IF NOT EXISTS domains_seq
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;

CREATE TABLE IF NOT EXISTS domains (
    id int check (id > 0) NOT NULL DEFAULT NEXTVAL ('domains_seq'),
    domain varchar(255) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (domain)
);

CREATE SEQUENCE IF NOT EXISTS accounts_seq
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;

CREATE TABLE IF NOT EXISTS accounts (
    id int check (id > 0) NOT NULL DEFAULT NEXTVAL ('accounts_seq'),
    username varchar(64) NOT NULL,
    domain varchar(255) NOT NULL,
    password varchar(255) NOT NULL,
    mail_crypt_salt VARCHAR(255) NOT NULL,
    quota int check (quota > 0) DEFAULT '0',
    enabled boolean DEFAULT '0',
    sendonly boolean DEFAULT '0',
    PRIMARY KEY (id),
    UNIQUE (username, domain),
    FOREIGN KEY (domain) REFERENCES domains (domain)
);

CREATE SEQUENCE IF NOT EXISTS aliases_seq
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;

CREATE TABLE IF NOT EXISTS aliases (
    id int check (id > 0) NOT NULL DEFAULT NEXTVAL ('aliases_seq'),
    source_username varchar(64),
    source_domain varchar(255) NOT NULL,
    destination_username varchar(64) NOT NULL,
    destination_domain varchar(255) NOT NULL,
    enabled boolean DEFAULT '0',
    PRIMARY KEY (id),
    UNIQUE (source_username, source_domain, destination_username, destination_domain),
    FOREIGN KEY (source_domain) REFERENCES domains (domain)
);

INSERT INTO domains (domain) VALUES ('localdomain');
INSERT INTO accounts (username, domain, password, mail_crypt_salt, quota, enabled, sendonly) VALUES ('noreply', 'localdomain', '$2y$05$28LTdSX2gZB/vWBfDNlF9u1W7sJmXM8y4r2lmE4E/UrHI0Fo1YMNK', '2007673425f621e70822741b9fd16d7e26b37b080337d622a670d0fb9f429ef6', 10, true, true);  -- nosemgrep
INSERT INTO accounts (username, domain, password, mail_crypt_salt, quota, enabled, sendonly) VALUES ('pwch1', 'localdomain', '$2y$05$28LTdSX2gZB/vWBfDNlF9u1W7sJmXM8y4r2lmE4E/UrHI0Fo1YMNK', '9ba8d8b8f64c33348a2f0efcd2e34c47c465c97e629340c4305a30a8fe7bfc87', 2048, true, false);  -- nosemgrep
INSERT INTO accounts (username, domain, password, mail_crypt_salt, quota, enabled, sendonly) VALUES ('pwch2', 'localdomain', '$2y$05$28LTdSX2gZB/vWBfDNlF9u1W7sJmXM8y4r2lmE4E/UrHI0Fo1YMNK', '336a1786cadc9c610118d5e6160f7e7eb67085bbd5212f487fc5179605167e42', 2048, true, false);  -- nosemgrep
INSERT INTO accounts (username, domain, password, mail_crypt_salt, quota, enabled, sendonly) VALUES ('pwch3', 'localdomain', '$2y$05$28LTdSX2gZB/vWBfDNlF9u1W7sJmXM8y4r2lmE4E/UrHI0Fo1YMNK', 'bd73a0fb00ab72f8f59ec7ca2e4564b7cbc03a8376c04d4255bdc0b37f57e5c5', 2048, true, false);  -- nosemgrep

ALTER TABLE domains OWNER TO vmail;
ALTER TABLE accounts OWNER TO vmail;
ALTER TABLE aliases OWNER TO vmail;
ALTER SEQUENCE domains_seq OWNER TO vmail;
ALTER SEQUENCE accounts_seq OWNER TO vmail;
ALTER SEQUENCE aliases_seq OWNER TO vmail;
