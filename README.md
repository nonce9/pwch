<br/>
<p align="center">
  <a href="https://github.com/nonce9/pwch">
    <img alt="pwch" src="screenshots/logo.svg" width="400"/>
  </a>
</p>
<br/>
<p align="center">
  <a href="https://ci.nonce.at/nonce9/pwch" title="Build Status">
    <img src="https://ci.nonce.at/api/badges/nonce9/pwch/status.svg" alt="status-badge" />
  </a>
  <a href="https://github.com/nonce9/pwch/actions/workflows/codeql.yml" title="CodeQL Status">
    <img src="https://github.com/nonce9/pwch/actions/workflows/codeql.yml/badge.svg" alt="status-badge" />
  </a>
</p>
<p align="center">
  <a href="https://github.com/nonce9/pwch/releases" title="Latest Release">
    <img src="https://img.shields.io/github/v/release/nonce9/pwch?style=flat&color=blue&display_name=tag&sort=semver" alt="status-badge" />
  </a>
  <a href='https://coveralls.io/github/nonce9/pwch?branch=main' title="Coverage Status">
    <img src='https://coveralls.io/repos/github/nonce9/pwch/badge.svg?branch=main' alt='Coverage Status' />
  </a>
    <img src="https://img.shields.io/badge/lines_of_code-642-blue" alt="status-badge" />
  <a href="https://goreportcard.com/report/github.com/nonce9/pwch" title="Go Report">
    <img src="https://goreportcard.com/badge/github.com/nonce9/pwch" alt="status-badge" />
  </a>
  <a href="https://github.com/nonce9/pwch/blob/main/LICENSE" title="License">
    <img src="https://img.shields.io/github/license/nonce9/pwch?style=flat&color=informational" alt="status-badge" />
  </a>
</p>
<p align="center">
  <a href="https://nonce.at/public.asc" title="Signing Key">
    <img alt="A Key" src="screenshots/key_link.svg" width="200" />
  </a>
</p>

# pwch (/piːwɪtʃ/)

pwch (short for *password change*) is a simple Go service for small mail server setups
with a PostgreSQL user store and dovecot IMAP server.
It will enable your users to change their password on their own via a pure html
selfservice portal and encrypt dovecot mailboxes with per user keys.
It's suppposed to be run on the same host as your dovecot IMAP server
installation.

## ATTENTION

Be sure to backup important emails BEFORE following the setup instructions.

You'll have to initially encrypt mailboxes for your users manually 
(see [here](https://github.com/nonce9/pwch#create-new-mail-user)).

pwch will handle all subsequent reencryptions during a password change.

### A note on security

Despite significant efforts to secure the application, there is a potential
vulnerability when calling the doveadm binary to reencrypt mailboxes.
This vulnerability arises when local attackers possess root permissions
and the required knowledge to intercept passwords that are written via stdin
to the doveadm command.
It is essential to recognize that the only truly secure method of
storing emails confidentially is through end-to-end encryption.

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

## What it looks like

The html and css files are fully customizable. This is what the default looks like.

![Page to submit email address](screenshots/submitEmail.png?raw=true)

![Page to change password](screenshots/changePassword.png?raw=true)

## Requirements

- Local dovecot installation with doveadm
- PostgreSQL database with pgcrypto extension enabled (contains user store)
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
    mail_crypt_require_encrypted_user_key = true
    mail_crypt_save_version = 2
}
```

Please take a look at the official [Documentation](https://doc.dovecot.org/configuration_manual/mail_crypt_plugin/)

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

6. Create the socket directory
```
# mkdir /run/pwch
# chown pwch:pwch /run/pwch
```

7. Copy the pwch binary to `/usr/local/bin/` and run `chmod +x` to make it executable.

8. Copy the doveadm_wrapper binary to `/usr/local/bin/` and first run `chown root:pwch`, then run `chmod 4750` to set the setuid bit.

9. Copy the [systemd unit file](config/pwch.service) to `/etc/systemd/system/` and run `systemctl daemon-reload`

10. Enable and start the service
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

2. Insert new user into database, e.g.
```
INSERT INTO accounts (username, domain, password, mail_crypt_salt, quota, enabled, sendonly) VALUES ('user', 'example.org', '$2y$14$28LTS...Fo1YMNK', ENCODE(gen_random_bytes(32), 'hex'), 2048, true, false);
```

3. When the user accounts is present in the database, run:

```
# doveadm -o plugin/mail_crypt_private_password=<salted-sha3-512-hashed password> mailbox cryptokey generate -u <user@example.org> -U
```

__INFO__: To calculate the salted sha3-512 hash of the password run this command inside postgres cli (pgcrypto must be enabled)

```
select encode(digest('<salt><plain_text_password>', 'sha3-512'), 'hex');
```

4. When the mailbox is encrypted tell your new user to change the password.

## How to test

Due to the external dependencies unit tests must be executed in a prepared environment.
I decided against mocking the dependencies as this would mean pulling in several
additional Go dependencies and writing a whole bunch of additional test code.

Instead I wrote an arguably disgusting all-in-one container image that is meant to be
used to run unit tests. However, this container functions as continuous integration test
as well. 

Here's how to run tests:

__INFO__: All listed commands are expected to be run from the repo's root directory.

1. Build the doveadm_wrapper binary
```
cd cmd/doveadm_wrapper
go build
```

2. Build the container image
```
cd test
docker build -t pwch-test .
```

3. Run the container in detached mode
```
docker run -d -v ${PWD}:/pwch --name pwch-test pwch-test
```
Or if you're running on SELinux:
```
docker run -d -v ${PWD}:/pwch:Z --name pwch-test pwch-test
```

4. Enter the container, navigate to the test file and run the tests
```
docker exec -it pwch-test /bin/bash
cd pwch/cmd/pwch
go test -v
```

That's it!

Remove the container when you're done:
```
docker stop pwch-test
docker rm pwch-test
```

## License

AGPL-3.0
