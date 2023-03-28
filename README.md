# pwch (/piːwɪtʃ/)

pwch is a simple Go service for small mail server setups. It will enable your
users to change their password on their own via a pure html selfservice portal
and encrypt dovecot mailboxes with per user keys. 
It's suppposed to be run on the same host as your dovecot IMAP server
installation and is (at the moment) suitable for a couple of mail users only.
I wrote this for my own private mail server setup. Read ahead to determine if
it suits your needs.

## WARNING

Try this software with great care only. DO NOT simply deploy it on your
production mail server without these considerations:

- I'm not a seasoned software dev. This is really a beginner's project. I'm a 
sysadmin who was looking for a solution to allow users to change their passwords 
on their own and encrypt their mailboxes.
- pwch will encrypt your user mailboxes. If anything fails these mails are gone
forever.

Feedback is much appreciated.

## Requirements

- Local dovecot installation with doveadm
- PostgreSQL database containing user store
- SMTP server with STARTTLS enabled
- Optional: AppArmor

## Database schema requirements

Take a look at [postgres.sql](config/postgres.sql) to set up your database.

## Dovecot requirements

See [dovecot-sql.conf](config/dovecot-sql.conf) to configure dovecot SQL queries.

You will have to configure dovecot as well to encrypt mailboxes:

```
mail_plugins = mail_crypt

plugin {
    mail_crypt_curve = secp521r1
    mail_crypt_require_encrypted_user_key = yes
    mail_crypt_save_version = 2
}
```

Please take a look at the official [Documentation](https://doc.dovecot.org/configuration_manual/mail_crypt_plugin/)

## What it does

- checks whether an email address exists in the users database
- sends one time links to change the password to existing email addresses
- enforces configurable password policy
- implements naive rate limiting when sending one time links
- encrypts mailboxes with per user keys derived from their password

## What it does not

- give an attacker hints whether an email address exists in the database
- there is no 'Forgot password' option. It's not possible by design. If you
forget your password you will need to reset it manually in the database. All
stored emails will be lost then.

## Roadmap

- [ ] Support simultaneous password changes (multi-user support)

## How it works

When a user enters an email address in the selfservice portal, pwch checks
whether the address is present in the database. If it is, the given address 
will receive an email containing a one time link which is valid for 10 minutes.

You still need your current password to set a new one. If all checks are passed
pwch will directly change the password in the database, run a wrapper script to 
reencrypt your mailbox and terminate all existing IMAP sessions for your user. 
This wrapper script executes doveadm commands. That is why dovecot/doveadm has
to be installed on the same host.
