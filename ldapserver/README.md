# LDAP test server

## Install

```bash
ansible-galaxy install -r requirements.yml
ansible up
```

## Test

```bash
ldapsearch \
  -H ldap://localhost:1389 \
  -x -D cn=admin,dc=example,dc=org -w P@55w0rd \
  -b dc=example,dc=org uid=john
```

## Manage

Go to http://localhost:8080/phpldapadmin and login with

```
user: cn=admin,dc=example,dc=org
password: P@55w0rd
```
