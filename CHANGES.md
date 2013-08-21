## Changes

* v0.1.1
    * Documentation changes due to renaming git repository of `ldapauth-fork`
* v0.1.0
    * Use [ldapauth-fork](https://github.com/vesse/node-ldapauth-fork) instead of
      [ldapauth](https://github.com/trentm/node-ldapauth)
        * ldapjs upgraded to 0.6.3
        * New options including `tlsOptions`
    * Refactored tests
* v0.0.6 (14 July 2013)
    * Fixes [#1](https://github.com/vesse/passport-ldapauth/issues/1)
    * Updated devDependencies
* v0.0.5 (16 April 2013)
    * Create LDAP client on every request to prevent socket being closed due
      to inactivity.
* v0.0.4 (14 April 2013)
    * Fixed passport-ldapauth version range.
* v0.0.3 (14 April 2013)
    * Initial release.
