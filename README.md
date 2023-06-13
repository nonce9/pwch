![banner](screenshots/banner.png?raw=true)

<p align="center">
  <a href="https://ci.nonce.at/nonce9/pwch" title="Build Status">
    <img src="https://ci.nonce.at/api/badges/nonce9/pwch/status.svg" alt="status-badge" />
  </a>
  <a href="https://github.com/nonce9/pwch/actions/workflows/codeql.yml" title="CodeQL Status">
    <img src="https://github.com/nonce9/pwch/actions/workflows/codeql.yml/badge.svg" alt="status-badge" />
  </a>
</p>
<p align="center">
  <a href='https://coveralls.io/github/nonce9/pwch?branch=main' title="Coverage Status">
    <img src='https://coveralls.io/repos/github/nonce9/pwch/badge.svg?branch=main' alt='Coverage Status' />
  </a>
  <a href="https://goreportcard.com/report/github.com/nonce9/pwch" title="Go Report">
    <img src="https://goreportcard.com/badge/github.com/nonce9/pwch" alt="status-badge" />
  </a>
<p/>
<p align="center">
  <a href="https://github.com/nonce9/pwch/releases" title="Latest Release">
    <img src="https://img.shields.io/github/v/release/nonce9/pwch?style=flat&color=blue&display_name=tag&sort=semver" alt="status-badge" />
  </a>
  <a href="https://github.com/nonce9/pwch/blob/main/LICENSE" title="License">
    <img src="https://img.shields.io/github/license/nonce9/pwch?style=flat&color=informational" alt="status-badge" />
  </a>
</p>
<p align="center">
  <a href="https://nonce.at/public.asc" title="Signing Key">
    <img src="https://img.shields.io/badge/Signing%20Key-ffac3f?style=flat&link=https://nonce.at/public.asc" alt="status-badge" />
  </a>
</p>

# pwch (/piːwɪtʃ/)

pwch (short for *password change*) is a simple Go service for small mail server setups
with a PostgreSQL user store and dovecot IMAP server.
It will enable your users to change their password on their own via a pure html
selfservice portal and encrypt dovecot mailboxes with per user keys.
It's suppposed to be run on the same host as your dovecot IMAP server
installation.

-----

## ATTENTION

Be sure to backup important emails BEFORE following the setup instructions.

You'll have to initially encrypt mailboxes for your users manually 
(see [here](https://github.com/nonce9/pwch#create-new-mail-user)).

pwch will handle all subsequent reencryptions during a password change.

-----

## What it does

- checks whether an email address exists in the user database
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
will receive an email containing a one time link which is valid for a
configurable amount of time.

You still need your current password to set a new one. If all checks are passed
pwch will directly change the password in the database, run a wrapper script to 
reencrypt your mailbox and terminate all existing IMAP sessions for your user.
If any of the above steps fail, pwch will rollback the changes.
The wrapper script executes doveadm commands. That is why dovecot/doveadm has
to be installed on the same host.

__Attention__: The wrapper script needs the setuid bit set.

-----

## What it looks like

The html and css files are fully customizable. This is what the default looks like.

![Page to submit email address](screenshots/submitEmail.png?raw=true)

![Page to change password](screenshots/changePassword.png?raw=true)

-----

## Requirements

- Local dovecot installation with doveadm
- PostgreSQL database containing user store
- SMTP server with STARTTLS enabled
- Optional: AppArmor

### Database schema requirements

Take a look at [postgres.sql](config/postgres.sql) for the minimal requirements
to set up your database.

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

You can use [this](https://github.com/nonce9/ansible-role-pwch)
ansible role to take care of the deployment if you like.

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

5. Create the html assets directory and copy the [html assets](assets/html/) to this directory.
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

## Create new mail user

pwch takes care of password changes of existing users. To create new users you
have to execute these steps manually.

1. Create initial user password

```
# doveadm pw -s BLF-CRYPT -r 14  // or whatever cost you have set
```

__ATTENTION__: Remove the `{BLF-CRYPT}` prefix before inserting the password into the database.

2. When the user accounts is present in the database, run:

```
# doveadm -o plugin/mail_crypt_private_password=<sha3-512-hashed password> mailbox cryptokey generate -u <user@example.org> -U
```

__INFO__: To calculate the sha3-512 hash of the password run this command inside postgres cli (pgcrypto must be activated)

```
select encode(digest('<plain_text_password>', 'sha3-512'), 'hex');
```

3. When the mailbox is encrypted tell your new user to change the password.

-----

## Integration testing

Integration testing has to be done locally with vagrant and ansible.
After installing these dependencies on your machine you have to build the pwch
binaries and move them to the correct directories in order to deploy them with
ansible on your vagrant box.

A simple `go build` in the `cmd/` directories should yield a `pwch` and a
`doveadm_wrapper` binary. Place these binaries in `vagrant/roles/pwch/files/`.

Then simply run `vagrant up` inside the `vagrant/` directory. If the ansible
playbook does not start automatically, run `vagrant provision`.
