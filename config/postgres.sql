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

ALTER TABLE domains OWNER TO <YOUR_POSTGRES_USER>;
ALTER TABLE accounts OWNER TO <YOUR_POSTGRES_USER>;
ALTER SEQUENCE domains_seq OWNER TO <YOUR_POSTGRES_USER>;
ALTER SEQUENCE accounts_seq OWNER TO <YOUR_POSTGRES_USER>;
