var should       = require('chai').Should(),
    LdapStrategy = require('passport-ldapauth').Strategy,
    request      = require('supertest'),
    ldapserver   = require('./ldapserver'),
    appserver    = require('./appserver');

var LDAP_PORT = 1389;

var expressapp = null;

// Base options that are cloned where needed to edit
var BASE_OPTS = {
  server: {
    url: 'ldap://localhost:' +  LDAP_PORT.toString(),
    adminDn: 'cn=root',
    adminPassword: 'secret',
    searchBase: 'ou=passport-ldapauth',
    searchFilter: '(uid={{username}})'
  }
},
BASE_TEST_OPTS = {
  no_callback: false
};

var start_servers = function(opts, test_opts) {
  return function(cb) {
    ldapserver.start(LDAP_PORT, function() {
      appserver.start(opts, test_opts, function(app) {
        expressapp = app;
        cb();
      });
    });
  }
}

var stop_servers = function(cb) {
  appserver.close(function() {
    ldapserver.close(function() {
      cb();
    });
  });
};

describe("LDAP authentication strategy", function() {

  describe("by itself", function() {

    it("should throw an error if no arguments are provided", function(cb) {
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
      var s = new LdapStrategy({}, function() {});
      (function() {
        s.authenticate({body: {username: 'valid', password: 'valid'}});
      }).should.throw(Error);
      cb();
    });

    it("should initialize without a verify callback", function(cb) {
      (function() {
        new LdapStrategy({server: {}})
      }).should.not.throw(Error);
      cb();
    });

  });

  describe("with basic settings", function() {

    before(start_servers(BASE_OPTS, BASE_TEST_OPTS));

    after(stop_servers);

    it("should return unauthorized if credentials are not given", function(cb) {
      request(expressapp)
        .post('/login')
        .send({})
        .expect(401)
        .end(cb);
    });

    it("should allow access with valid credentials", function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'valid', password: 'valid'})
        .expect(200)
        .end(cb);
    });

    it("should allow access with valid credentials in query string", function(cb) {
      request(expressapp)
        .post('/login?username=valid&password=valid')
        .expect(200)
        .end(cb);
    });

    it("should return unauthorized with invalid credentials", function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'valid', password: 'invvalid'})
        .expect(401)
        .end(cb);
    });

    it("should return unauthorized with non-existing user", function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'nonexisting', password: 'invvalid'})
        .expect(401)
        .end(cb);
    });
  });

  describe("without a verify callback", function() {
    before(start_servers(BASE_OPTS, {no_callback: true}));

    after(stop_servers);

    it("should still authenticate", function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'valid', password: 'valid'})
        .expect(200)
        .end(cb);
    });

    it("should reject invalid event", function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'valid', password: 'invalid'})
        .expect(401)
        .end(cb);
    });
  });

  describe("with optional options", function() {

    afterEach(stop_servers);

    it("should read given fields instead of defaults", function(cb) {
      var OPTS = JSON.parse(JSON.stringify(BASE_OPTS));
      OPTS.usernameField = 'ldapuname';
      OPTS.passwordField = 'ldappwd';

      start_servers(OPTS, BASE_TEST_OPTS)(function() {
        request(expressapp)
          .post('/login')
          .send({ldapuname: 'valid', ldappwd: 'valid'})
          .expect(200)
          .end(cb);
      });
    });

    it("should pass request to verify callback if defined so", function(cb) {
      var OPTS = JSON.parse(JSON.stringify(BASE_OPTS));
      OPTS.passReqToCallback = true;

      start_servers(OPTS, BASE_TEST_OPTS)(function() {
        var req = {body: {username: 'valid', password: 'valid', testkey: 1}},
            s   = new LdapStrategy(OPTS, function(req, user, done) {
              req.should.have.keys('body');
              req.body.should.have.keys(['username', 'password', 'testkey']);
              done(null, user);
            });

        s.success = function(user) {
          should.exist(user);
          user.uid.should.equal('valid');
          cb();
        };

        s.authenticate(req);
      });
    });
  });
});
