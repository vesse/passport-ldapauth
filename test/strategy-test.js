var should       = require('chai').Should(),
    LdapStrategy = require('passport-ldapauth'),
    request      = require('supertest'),
    basicAuth    = require('basic-auth'),
    ldapserver   = require('./ldapserver'),
    appserver    = require('./appserver');

var LDAP_PORT = 1399;

var expressapp = null;

// Base options that are cloned where needed to edit
var BASE_OPTS = {
  server: {
    url: 'ldap://localhost:' +  LDAP_PORT.toString(),
    bindDn: 'cn=root',
    bindCredentials: 'secret',
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

describe('LDAP authentication strategy', function() {

  describe('by itself', function() {

    it('should export Strategy constructor directly', function(cb) {
      require('passport-ldapauth').should.be.a('function');
      cb();
    });

    it('should export Strategy constructor separately as well', function(cb) {
      var strategy = require('passport-ldapauth').Strategy;
      strategy.should.be.a('function');
      (function() {
        new strategy(BASE_OPTS);
      }).should.not.throw(Error);
      cb();
    });

    it('should be named ldapauth', function(cb) {
      var s = new LdapStrategy(BASE_OPTS);
      s.name.should.equal('ldapauth');
      cb();
    });

    it('should throw an error if no arguments are provided', function(cb) {
      (function() {
        new LdapStrategy();
      }).should.throw(Error);
      cb();
    });

    it('should throw an error if options are not accepted by ldapauth', function(cb) {
      var s = new LdapStrategy({}, function() {});
      (function() {
        s.authenticate({body: {username: 'valid', password: 'valid'}});
      }).should.throw(Error);
      cb();
    });

    it('should initialize without a verify callback', function(cb) {
      (function() {
        new LdapStrategy({server: {}})
      }).should.not.throw(Error);
      cb();
    });

  });

  describe('with basic settings', function() {

    before(start_servers(BASE_OPTS, BASE_TEST_OPTS));

    after(stop_servers);

    it('should return unauthorized if credentials are not given', function(cb) {
      request(expressapp)
        .post('/login')
        .send({})
        .expect(400)
        .end(cb);
    });

    it('should allow access with valid credentials', function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'valid', password: 'valid'})
        .expect(200)
        .end(cb);
    });

    it('should allow access with valid credentials in query string', function(cb) {
      request(expressapp)
        .post('/login?username=valid&password=valid')
        .expect(200)
        .end(cb);
    });

    it('should return unauthorized with invalid credentials', function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'valid', password: 'invalid'})
        .expect(401)
        .end(cb);
    });

    it('should return unauthorized with non-existing user', function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'nonexisting', password: 'invalid'})
        .expect(401)
        .end(cb);
    });

    it('should return more specific flash message for AD reply', function(cb) {
      request(expressapp)
        .post('/custom-cb-login')
        .send({username: 'ms-ad', password: 'invalid'})
        .expect(401)
        .end(function(err, res) {
          should.not.exist(err);
          res.body.message.should.equal('Account disabled')
          cb(err, res);
        });
    });
  });

  describe('without a verify callback', function() {
    before(start_servers(BASE_OPTS, {no_callback: true}));

    after(stop_servers);

    it('should still authenticate', function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'valid', password: 'valid'})
        .expect(200)
        .end(cb);
    });

    it('should reject invalid event', function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'valid', password: 'invalid'})
        .expect(401)
        .end(cb);
    });
  });

  describe('with optional options', function() {

    afterEach(stop_servers);

    it('should read given fields instead of defaults', function(cb) {
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

    it('should pass request to verify callback if defined so', function(cb) {
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

        s.error = function() {}; // Just to have this when not run via passport

        s.authenticate(req);
      });
    });

    it('should allow access with valid credentials in the header', function(cb) {
      var OPTS = JSON.parse(JSON.stringify(BASE_OPTS));
      OPTS.credentialsLookup = basicAuth;

      start_servers(OPTS, BASE_TEST_OPTS)(function() {
        request(expressapp)
          .post('/login')
          .set('Authorization', 'Basic dmFsaWQ6dmFsaWQ=')
          .expect(200)
          .end(cb);
      });
    });

    it('should support returning a custom status code when credentials are missing', function(cb) {
      var OPTS = JSON.parse(JSON.stringify(BASE_OPTS));
      OPTS.missingCredentialsStatus = 401;

      start_servers(OPTS, BASE_TEST_OPTS)(function() {
        request(expressapp)
          .post('/login')
          .expect(401)
          .end(cb);
      });
    });
  });

  describe('with options as function', function() {
    var OPTS = JSON.parse(JSON.stringify(BASE_OPTS));
    OPTS.usernameField = 'cb_uname';
    OPTS.passwordField = 'cb_pwd';

    var opts = function(cb) {
      process.nextTick(function() {
        cb(null, OPTS);
      });
    };

    before(start_servers(opts, BASE_TEST_OPTS));
    after(stop_servers);

    it('should use the options returned from the function', function(cb) {
      request(expressapp)
        .post('/login')
        .send({cb_uname: 'valid', cb_pwd: 'valid'})
        .expect(200)
        .end(cb);
    });

    it('should not allow login if using wrong fields', function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'valid', password: 'valid'})
        .expect(400)
        .end(cb);
    });
  });

  describe('with options as function returning dynamic sets', function() {
    var OPTS = JSON.parse(JSON.stringify(BASE_OPTS));
    OPTS.usernameField = 'first_uname';
    OPTS.passwordField = 'first_pwd';

    var OPTS2 = JSON.parse(JSON.stringify(BASE_OPTS));
    OPTS2.usernameField = 'second_uname';
    OPTS2.passwordField = 'second_pwd';

    var opts = function(req, cb) {
      process.nextTick(function() {
        if (req.body.set == 'first') {
          cb(null, OPTS);
        } else {
          cb(null, OPTS2);
        }
      });
    };

    before(start_servers(opts, BASE_TEST_OPTS));
    after(stop_servers);

    it('should use the first set options returned from the function', function(cb) {
      request(expressapp)
        .post('/login')
        .send({first_uname: 'valid', first_pwd: 'valid', set: 'first'})
        .expect(200)
        .end(cb);
    });

    it('should not allow first set login if using wrong fields', function(cb) {
      request(expressapp)
        .post('/login')
        .send({second_uname: 'valid', second_pwd: 'valid', set: 'first'})
        .expect(400)
        .end(cb);
    });

    it('should use the second set options returned from the function', function(cb) {
      request(expressapp)
        .post('/login')
        .send({second_uname: 'valid', second_pwd: 'valid', set: 'second'})
        .expect(200)
        .end(cb);
    });

    it('should not allow second set login if using wrong fields', function(cb) {
      request(expressapp)
        .post('/login')
        .send({first_uname: 'valid', first_pwd: 'valid', set: 'second'})
        .expect(400)
        .end(cb);
    });
  });

  describe('with group fetch settings defined', function() {
    var OPTS;

    var groupTest = function(opts, cb) {
      start_servers(opts, BASE_TEST_OPTS)(function() {
        var req = {body: {username: 'valid', password: 'valid'}},
            s   = new LdapStrategy(opts, function(user, done) {
              req.should.have.keys('body');
              req.body.should.have.keys(['username', 'password']);
              done(null, user);
            });

        s.success = function(user) {
          should.exist(user);
          user.uid.should.equal('valid');
          user._groups.length.should.equal(2);
          user._groups[0].name.should.equal('Group 1');
          user._groups[1].name.should.equal('Group 2');
          cb();
        };

        s.error = function() {}; // Just to have this when not run via passport

        s.authenticate(req);
      });
    }

    beforeEach(function(cb) {
      OPTS = JSON.parse(JSON.stringify(BASE_OPTS));
      OPTS.server.groupSearchBase = 'ou=passport-ldapauth';
      OPTS.server.groupSearchScope = 'sub';
      cb();
    });

    afterEach(stop_servers);

    it('should return groups for user with string filter', function(cb) {
      OPTS.server.groupSearchFilter = '(member={{dn}})';
      groupTest(OPTS, cb);
    });

    it('should return groups for user with function filter', function(cb) {
      OPTS.server.groupSearchFilter = function(user) {
        return '(member={{dn}})'.replace(/{{dn}}/, user.dn)
      };
      groupTest(OPTS, cb);
    });
  });

  describe('with invalid LDAP url', function() {
    var OPTS = JSON.parse(JSON.stringify(BASE_OPTS));
    OPTS.server.url = 'ldap://nonexistingdomain.fi:389';

    before(start_servers(OPTS, BASE_TEST_OPTS));

    after(stop_servers);

    it('should return with an error', function(cb) {
      request(expressapp)
        .post('/login')
        .send({username: 'valid', password: 'valid'})
        .expect(500)
        .end(cb);
    });
  });

  describe('with handleErrorsAsFailures', function() {
    after(stop_servers);

    it('should return with a failure', function(cb) {
      var callbackCalled = false;
      var testCompleted = false;
      var OPTS = JSON.parse(JSON.stringify(BASE_OPTS));
      OPTS.server.url = 'ldap://nonexistingdomain.fi:389';
      OPTS.handleErrorsAsFailures = true;
      OPTS.failureErrorCallback = function(err) {
        should.exist(err);
        callbackCalled = true;
      }

      start_servers(OPTS, BASE_TEST_OPTS)(function() {
        var req = {body: {username: 'valid', password: 'valid'}},
            s   = new LdapStrategy(OPTS);

        s.fail = function(msg, code) {
          code.should.equal(500);
          callbackCalled.should.be.true;
          // There can be more than one event emitted and mocha fails
          // if callback is called more than once
          if (testCompleted === false) {
            testCompleted = true;
            cb();
          }
        }

        s.error = function() {}; // Just to have this when not run via passport

        s.authenticate(req);
      });
    });
  });
});
