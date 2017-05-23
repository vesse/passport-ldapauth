# LDAP test server

**NOTE:** Not working anymore, latest `slapd` apparently does not create the example DN and thus `mrlesmithjr.openldap` playbook fails.

## Install

```bash
ansible-galaxy install -r requirements.yml
vagrant up
```

## Test

```bash
ldapsearch \
  -H ldap://localhost:1389 \
  -x -D cn=admin,dc=example,dc=org -w P@55w0rd \
  -b dc=example,dc=org uid=john
```

## Manage

Go to [`http://localhost:8080/phpldapadmin`](http://localhost:8080/phpldapadmin) and login with

```
user: cn=admin,dc=example,dc=org
password: P@55w0rd
```

## Use

There's a user `uid=john` in `ou=People,dc=example,dc=org` with password `P@55w0rd`.
