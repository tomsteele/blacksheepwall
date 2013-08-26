// Copyright (c) 2012 Tom Steele, Jason Doyle
// See the file license.txt for copying permission
var async = require('async');
var dns = require('dns');
var tls = require('tls');
var domain = require('domain');
var https = require('https');
var http = require('http');
var url = require('url');
var winston = require('winston');

module.exports = blacksheepwall;
BSW.prototype = {};

function blacksheepwall(options) {
  return new BSW(options);
}

function BSW(options) {
  var self = this;
  options = options || {};
  self.hosts = options.hosts || null;
  self.domain = options.domain || null;
  self.names = options.names || null;
  self.concurrency = options.concurrency || 1000;
  self.results = []; 
}

// Loops over self.names looking for the ip of
// name + self.domain. 
BSW.prototype.dictionary = function(callback) {
   var self = this;
   if (!self.domain) {
     callback('Missing domain');
   } 
   if (!self.names) {
     callback('Missing names list');
   }
   async.eachLimit(self.names, self.concurrency, function(subDomain, cb) {
     var uri = subDomain + '.' + self.domain;
     var d = domain.create();
     d.on('error', function(err) {
       if (typeof process.env.SHOW_BSW_ERRORS !== 'undefined') {
         winston.error(err);
       }
       cb();
     });
     d.run(function() {
       dns.resolve4(uri, function(err, addresses) {
         if (err) {
           cb();
         } else {
           self.results.push({ip: addresses[0], name: uri, src: 'dictionary'});
           cb();
         }
       });
     });
   }, callback);
};

// Performs a reverse lookup of all self.hosts
BSW.prototype.reverse = function(callback) {
  var self = this;
  if (!self.hosts) {
    callback('Missing host list');
  }
  async.eachLimit(self.hosts, self.concurrency, function(host, cb) {
    var d = domain.create();
    d.on('error', function(err) {
      if (typeof process.env.SHOW_BSW_ERRORS !== 'undefined') {
        winston.error(err);
      }
      cb();
    });
    d.run(function() {
      dns.reverse(host, function(err, domains) {
        if (err) {
          cb();
        } else {
          process.nextTick(function() {
            domains.forEach(function(domain) {
              self.results.push({ip: host, name: domain, src: 'reverse'});
            });
            cb();
          });
        }
      });
    });
  }, callback);
};

// Attempt to connect to each host on port 443, reading names
// from the SSL certificate.
BSW.prototype.ssl = function(callback) {
  var self = this;
  if (!self.hosts) {
    callback('Missing host list');
  }
  async.eachLimit(self.hosts, self.concurrency, function(host, cb) {
    var d = domain.create();
    d.on('error', function(err) {
      if (typeof process.env.SHOW_BSW_ERRORS !== 'undefined') {
        winston.error(err);
      }
      cb();
    });
    d.run(function() {
      var tlsOptions = {host: host, port: 443, rejectUnauthorized: false};
      var cleartextStream = tls.connect(tlsOptions, function() {
        var certificate = cleartextStream.getPeerCertificate();
        var cn = certificate['subject']['CN'];
        if (typeof cn === 'string' && cn.match(/[a-z]+/i)) {
          self.results.push({ip: host, name: cn, src: 'certificate'});
        }
        if (typeof certificate['subjectalname'] !== 'undefined') {
          var subjectNames = certificate['subjectalname'].split(',');
          process.nextTick(function() {
            subjectNames.forEach(function(sn) {
              var name = sn.substr(sn.indexOf(':') + 1);
              self.results.push({ip: host, name: name, src: 'certificate'});
            });
          });
        }
        cb();
      });
      cleartextStream.setTimeout(600, function() {
        cleartextStream.end();
      });
      cleartextStream.on('error', function() {
        cb();
      });
    });
  }, callback);
};


