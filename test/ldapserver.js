var ldap = require('ldapjs');

authorize = function(req, res, next) {
  return next();
};

var SUFFIX = 'ou=passport-ldapauth';
var server = null;

db = {
  'valid': {
    dn: 'cn=valid, ou=passport-ldapauth',
    attributes:  {
      uid:  'valid',
      name: 'Valid User'
    }
  }
};

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
    var dn = req.dn.toString();
    if (dn !== 'cn=valid, ou=passport-ldapauth' || req.credentials !== 'valid') {
      return next(new ldap.InvalidCredentialsError());
    }
    res.end();
    return next();
  });

  server.search(SUFFIX, authorize, function(req, res, next) {
    if (req.filter.value == 'valid') {
      res.send(db['valid']);
    }
    res.end();
    return next();
  });

  server.listen(port, function() {
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
