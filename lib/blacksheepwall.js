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

// Use the Bing API to do IP address to name lookups
// options should be a object containing host, authentication header, and path;
// Eg. { host: 'api.datamarket.azure.com', auth: key + key, path: '/Data.ashx/Bing/Search/v1/Web' }
BSW.prototype.bingApi = function(options, callback) {
  var self = this;
  async.eachLimit(self.hosts, 20, function(host, cb) {
    var d = domain.create();
    d.on('error', function(err) {
      if (typeof process.env.SHOW_BSW_ERRORS !== 'undefined') {
        winston.error(err.message);
      }
      cb();
    });
    d.run(function() {
      bingQuery(0);
      // Recursive function to handle offset
      function bingQuery(offset) {
        var message = '';
        var count = 50;
        var queryString = '?Query=%27ip:' + host + '%27' + '&$top=' + count +
                          '&$skip=' + offset + '&Adult=%27off%27&$format=json';
        // Replace the previous query string
        options.path = options.path.replace(/\?.*/, queryString);
        var req = https.request(options, function(res) {
          res.on('data', function(chunk) {
            message += chunk;
          });
          res.on('end', function() {
            var urls = JSON.parse(message).d.results;
            process.nextTick(function() {
              urls.forEach(function(element) {
                self.results.push({ip: host, name: url.parse(element.Url)['hostname'], src: 'Bing-API'});
              });
            });
            if (urls.length == count) {
              bingQuery(offset += count);
            } else {
              cb();
            }
          });
        });
        req.end();
        req.on('error', function() {
          cb();
        });
      }
    });
  }, callback);
};

// Using Bing web search
BSW.prototype.bing = function(callback) {
  var self = this;
  async.eachLimit(self.hosts, 20, function(host, cb) {
    var d = domain.create();
    d.on('error', function(err) {
      if (typeof process.env.SHOW_BSW_ERRORS !== 'undefined') {
        winston.error(err);
      }
      cb();
    });
    d.run(function() {
      var offset = 0;
      var message = '';
      var queryString = '?q=ip:' + host + '&first=' + offset;
      var options = { hostname: 'www.bing.com', path: '/search' + queryString};
      var req = http.request(options, function(res) {
        res.on('data', function(chunk) {
          message += chunk;
        });
        res.on('end', function() {
          var urls = message.match(/\"><cite>.*?<\/cite>/gm);
          if (urls) {
            process.nextTick(function() {
              urls.forEach(function(u) {
                u = u.match(/cite>(.*?)</i);
                if (u) {
                  if (u[1].search('//')) {
                    u[1] = 'http://'.concat(u[1]); // make url.parse happy
                  }
                  self.results.push({ ip: host, name: url.parse(u[1])['hostname'], src: 'Bing'});
                }
              });
            });
          }
          cb();
        });
      });
      req.end();
      req.on('error', function() {
        cb();
      });
    });
  }, callback);
};

