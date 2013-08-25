// Copyright (c) 2012 Tom Steele, Jason Doyle
// See the file license.txt for copying permission
var async = require('async');
var dns = require('dns');
var tls = require('tls');
var https = require('https');
var http = require('http');
var url = require('url');

module.exports = blacksheepwall;
blacksheepwall.prototype = {};

function blacksheepwall(options) {
  return new BSW(options);
}

function BSW(options) {
  var self = this;
  var options = options || {};
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
   var q = async.queue(function(subDomain, qCallback) {
     var uri = subDomain + '.' + self.domain;
     dns.resolve4(uri, function(err, addresses) {
       if (err) {
         qCallback();
       } else {
         self.results.push({ip: addresses[0], name: uri, src: 'dictionary'});
         qCallback();
       }
     });
   }, self.concurrency);
   q.drain = callback;
   q.push(self.names);
};

// Performs a reverse lookup of all self.hosts
BSW.prototype.reverse = function(callback) {
  var self = this;
  var q = async.queue(function(host, qCallback) {
    dns.reverse(host, function(err, domains) {
      if (err) {
        qCallback();
      } else {
        process.nextTick(function() {
          domains.forEach(function(domain) {
            self.results.push({ip: host, name: domain, src: 'reverse'});
          });
          qCallback();
        });
      }
    });
  }, self.concurrency);
  q.drain = callback;
  q.push(self.hosts);
};
