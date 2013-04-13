var should       = require('chai').Should(),
    LdapStrategy = require('passport-ldapauth').Strategy;

describe("LDAP authentication strategy", function() {
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
