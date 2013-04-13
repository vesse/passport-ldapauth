var ldap = require('ldapjs');

authorize = function(req, res, next) {
  if (!req.connection.ldap.bindDN.equals('cn=root')) {
    return next(new ldap.InsufficientAccessRightsError());
  }
  return next();
};

var SUFFIX = 'ou=passport-ldapauth';
var server = null;

exports.start = function(port, cb) {
  if (server) {
    if (typeof cb === 'function') return cb();
    return;
  }

  server = ldap.createServer();

  server.bind('cn=root', function(req, res, next) {
    if (req.dn.toString() !== 'cn=root' || req.credentials !== 'secret') {
      return next(new ldap.InvalidCredentialsError());
    }
    res.end();
    return next();
  });

  server.bind(SUFFIX, authorize, function(req, res, next) {

  });

  server.search(SUFFIX, authorize, function(req, res, next) {

  });

  server.listen(port, function() {
    console.log("LDAP server up at %s", server.url);
    if (typeof cb === 'function') return cb();
  });
};

exports.close = function(cb) {
  if (server) server.close();
  server = null;
  if (typeof cb === 'function') return cb();
  return;
};

if (!module.parent) {
  exports.start(1389);
}
