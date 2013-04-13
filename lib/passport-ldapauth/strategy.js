/**
 * Passport wrapper for ldapauth
 */
var passport = require('passport'),
    LdapAuth = require('ldapauth'),
    util     = require('util');

/**
 * Strategy constructor
 *
 * Options:
 * - `server`  options for ldapauth, see https://github.com/trentm/node-ldapauth
 * - `usernameField`  field name where the username is found, defaults to _username_
 * - `passwordField`  field name where the password is found, defaults to _password_
 * - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 */
function Strategy(options, verify) {
  if (!verify)  throw new Error('LDAP authentication strategy requires a verify function');
  if (!options) throw new Error('LDAP authentication strategy requires options');

  passport.Strategy.call(this);

  this.name    = 'ldapauth';
  this.options = options;

  this.options.usernameField || (this.options.usernameField = 'username');
  this.options.passwordField || (this.options.passwordField = 'password');

  this.ldap = new LdapAuth(this.options.server);
};

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {

};

module.exports = Strategy;
