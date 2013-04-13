var should       = require('chai').Should(),
    LdapStrategy = require('passport-ldapauth').Strategy,
    ldapserver   = require('./ldapserver'),
    appserver    = require('./appserver');

LDAP_PORT = 1389;

describe("LDAP authentication strategy", function() {
  before(function(cb) {
    ldapserver.start(LDAP_PORT, function() {
      appserver.start(LDAP_PORT, function() {
        cb();
      });
    });
  });

  after(function(cb) {
    appserver.close(function() {
      ldapserver.close(function() {
        cb();
      });
    });
  });

  it("should throw an error if verify callback is not provided", function(cb) {
    (function() {
      new LdapStrategy();
    }).should.throw(Error);
    cb();
  });

  it("should throw an error if options are not provided", function(cb) {
    (function() {
      new LdapStrategy(function() {});
    }).should.throw(Error);
    cb();
  });

  it("should throw an error if options are not accepted by ldapauth", function(cb) {
    (function() {
      new LdapStrategy({}, function() {});
    }).should.throw(Error);
    cb();
  })
});
