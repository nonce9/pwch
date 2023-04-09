# pwch (/piːwɪtʃ/)

![build](https://github.com/nonce9/pwch/actions/workflows/build.yml/badge.svg)

pwch (short for *password change*) is a simple Go service for small mail server setups.
It will enable your users to change their password on their own via a pure html
selfservice portal and encrypt dovecot mailboxes with per user keys.
It's suppposed to be run on the same host as your dovecot IMAP server
installation and is (at the moment) suitable for a couple of mail users only.
I wrote this for my own private mail server setup. Read ahead to determine if
it suits your needs.

-----

## WARNING

Try this software with great care only. DO NOT simply deploy it on your
production mail server without these considerations:

- This software is currently in alpha status and hardly tested.
- I'm not a seasoned software dev. This is really a beginner's project. I'm a 
sysadmin who was looking for a solution to allow users to change their passwords 
on their own and encrypt their mailboxes.
- pwch will encrypt your user mailboxes. If anything fails these mails are gone
forever.

Feedback is much appreciated.

-----

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

## How it works

When a user enters an email address in the selfservice portal, pwch checks
whether the address is present in the database. If it is, the given address 
will receive an email containing a one time link which is valid for 10 minutes.

You still need your current password to set a new one. If all checks are passed
pwch will directly change the password in the database, run a wrapper script to 
reencrypt your mailbox and terminate all existing IMAP sessions for your user. 
This wrapper script executes doveadm commands. That is why dovecot/doveadm has
to be installed on the same host.

__Attention__: The wrapper script needs the setuid bit set.

-----

## Roadmap

- [ ] Support simultaneous password changes (multi-user support)

-----

## What it looks like

The html and css files are fully customizable. This is what the default looks like.

![Page to submit email address](screenshots/submitEmail.jpg?raw=true)

![Page to change password](screenshots/changePassword.jpg?raw=true)

-----

## Requirements

- Local dovecot installation with doveadm
- PostgreSQL database containing user store
- SMTP server with STARTTLS enabled
- Optional: AppArmor

### Database schema requirements

Take a look at [postgres.sql](config/postgres.sql) to set up your database.

### Dovecot requirements

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

-----

## How to deploy

1. Create a system group
```
# groupadd --system pwch
```

2. Create a system user
```
# useradd --gid pwch --no-create-home --shell /sbin/nologin --system pwch
```

3. Create the config directory
```
# mkdir /etc/pwch
```

4. Create the config file at `/etc/pwch/config.yml`. Set owner and group to `pwch`
and remove all permissions to others.

5. Create the html assets directory and copy the [html assets](html/) to this directory.
```
# mkdir /usr/local/src/pwch
```

6. Copy the pwch binary to `/usr/local/bin/` and run `chmod +x` to make it executable.

7. Copy the doveadm_wrapper binary to `/usr/local/bin/` and first run `chown root:pwch`, then run `chmod 4750` to set the setuid bit.

8. Copy the [systemd unit file](config/pwch.service) to `/etc/systemd/system/` and run `systemctl daemon-reload`

9. Enable and start the service
```
# systemctl enable pwch.service
# systemctl start pwch.service
```

### AppArmor (Optional)

The pwch policy allows PostgreSQL unix socket connections only.

1. Copy the AppArmor policies to `/etc/apparmor.d/usr.local.bin.pwch` and
`/etc/apparmor.d/usr.local.bin.doveadm_wrapper`

2. Load the policies with
```
apparmor_parser -r /etc/apparmor.d/usr.local.bin.pwch /etc/apparmor.d/usr.local.bin.doveadm_wrapper
```

