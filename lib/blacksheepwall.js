// Copyright (c) 2012 Tom Steele, Jason Doyle
// See the file license.txt for copying permission
var async = require('async');
var dns = require('dns');
var tls = require('tls');
var https = require('https');
var http = require('http');
var url = require('url');

//
// dictionary based lookup
//
exports.dictionary = function(domain, names, concurrency, callback) {
  var results = [];
  var q = async.queue(function (lookup, queueCallback) {
    lookup = lookup + '.' + domain;
    dns.resolve4(lookup, function (err, addresses) {
      if (err) {
       queueCallback();
      }
      else {
        results.push( { ip: addresses[0],
                        name:  lookup,
                        src: 'dictionary'
                       }
                     );
        queueCallback();
      }
    });
  }, concurrency);
  q.drain = function() { callback(results) };
  q.push(names);
};

//
// reverse ip lookup
//
exports.reverse = function(hosts, concurrency, callback) {
  var results = [];
  var q = async.queue(function (host, queueCallback) {
    dns.reverse(host, function (err, domains) {
      if (err) {
        queueCallback();
      }
      else {
        domains.forEach(function(domain) {
          results.push( { ip: host,
                          name: domain,
                          src: 'reverse'
                         });
        });
        queueCallback();
      }
    });
  }, concurrency);
  q.drain = function() { callback(results) };
  q.push(hosts);
};
  
//
// grabs hostnames from ssl certificates
//
exports.cert = function(hosts, concurrency, callback) {
  var results = [];
  var q = async.queue(function (host, queueCallback) {
    var cleartextStream = tls.connect(443, host, function () {
      var cert = cleartextStream.getPeerCertificate();
      var cn = cert['subject']['CN'];
      var sns = cert['subjectalname'];
      if (cn) {
        results.push( { ip: host,
                        name: cn,
                        src: 'cert'
                      });
      }
      if (sns) {
        sns.forEach(function(sn) {
          results.push( { ip: host,
                          name: sn,
                          src: 'cert'
                        });
        });
      }
     queueCallback();
    });
    cleartextStream.on('error', queueCallback);
    cleartextStream.on('data', queueCallback);
    cleartextStream.on('end', queueCallback);
  }, concurrency);
  q.drain = function() { callback(results) };
  q.push(hosts);
};

//
// query bing for vhosts using api
//
exports.bingApi = function(hosts, concurrency, options, callback) {
  var results = [];
  var q = async.queue(function (host, queueCallback) {
    var count = 50;
    var offset = 0;
    var message = '';
    var params = '?Query=%27ip:' + host + '%27' +
                 '&$top=' + count +
                 '&$skip=' + offset +
                 '&Adult=%27Off%27&$format=json';
    options.path = options.path.replace(/\?.*/, params);
    var req = https.request(options, function(res) {
      res.on('data', function(chunk) {
        message += chunk;
      });

      res.on('end', function() {
        var urls = JSON.parse(message).d.results;
        urls.forEach(function(element) {
            results.push({ ip: host,
                           name: url.parse(element.Url)['hostname'],
                           src: 'bing-api'
                         });
        });
        queueCallback();
      });
    });
    req.end();
    req.on('error', function() {
      queueCallback();
    });
  }, concurrency);
  q.drain = function() { callback(results) };
  q.push(hosts);
};

//
// query bing for vhosts without api key
//
exports.bing = function(hosts, concurrency, callback) {
  var results = [];
  var q = async.queue(function (host, queueCallback) {
    var offset = 0;
    var message = '';
    var params = '?q=ip:' + host +
                 '&first=' + offset;
    var options = { hostname: 'www.bing.com',
                    path: '/search' + params };
    var req = http.request(options, function(res) {
      res.on('data', function(chunk) {
        message += chunk;
      });

      res.on('end', function() {
        var urls = message.match(/\"><cite>.*?<\/cite>/gm);
        if (urls) {
          urls.forEach(function(u) {
            u = u.match(/cite>(.*?)</i);
            if (u) {
              if (u[1].search('//')) {
                u[1] = 'http://'.concat(u[1]); // make url.parse happy
              }
              results.push({ ip: host,
                             name: url.parse(u[1])['hostname'],
                             src: 'bing'
                           });
            }
          });
        }
        queueCallback();
      });
    });
    req.end();
    req.on('error', function() {
      queueCallback();
    });
  }, concurrency);
  q.drain = function() { callback(results) };
  q.push(hosts);
};

//
// grab name records from robtex.com one c-network at a time
//
exports.robtex = function(hosts, concurrency, callback) {
  var cNetworks = []; // unique C-networks 
  for (var i = 0; i < hosts.length; i++) {
    var dup = false;
    var cnet = hosts[i].split(".", 3).join(".");
    for (var c = 0; c < cNetworks.length; c++) {
      if (cnet == cNetworks[c]) {
        dup = true;
        break;
      }
    }
    if (dup) {
      break;
    }  
    cNetworks.push(cnet);
  }
  var results = [];
  var q = async.queue(function (cnet, queueCallback) {
    var message = '';    
    var options = {
      hostname: 'cnet.robtex.com',
      path: '/' + cnet + '.html'
    };
    var req = http.request(options, function(res) {
      res.on('data', function(chunk) {
        message += chunk;
      });
      res.on('end', function() {
        var htmlRows = message.match(/<tr>[\w\W]*?<\/tr>/mg);
        for (var i = 0; i < htmlRows.length; i++) {
          var ipMatch = htmlRows[i].match(/ip\.robtex\.com\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\./);
          if (ipMatch) {
            var ipaddr = ipMatch[1];
            for (var c = 0; c < hosts.length; c++) { // check if ip in scope
              if (ipaddr == hosts[c]) {
                var hostname = htmlRows[i].match(/>([a-z0-9-\.]{2,}[a-z])<\/a>/i);
                if (hostname) {
                    results.push( { ip: ipaddr,
                                    name: hostname[1],
                                    src: 'robtex'
                                  });
                }
              }
            }
          }
          ipMatch = null;
          hostname = null;
        }
        queueCallback();
      });
    });
    req.end();
    req.on('error', function() {
      queueCallback();
    });
  }, concurrency);
  q.drain = function () { callback(results) };
  q.push(cNetworks);
};

//
// parse http response headers
// TODO: build regex to match all header params
//
exports.headersHttp = function(hosts, concurrency, callback) {
  var results = [];
  var q = async.queue(function (host, queueCallback) {
    var req = http.request({'host': host}, function(res) {
      res.on('end', function() {
        if (res.headers.location) {
          var hostname = url.parse(res.headers.location)['hostname'];
          // we don't want an ip
          if (hostname && hostname.match(/[a-zA-Z]+/)) {
            results.push( { ip: host,
                            name: hostname,
                            src: 'headers-http'
                          });
          }
        }
        queueCallback();
      });
    });
    req.end();
    req.on('error', function() {
      queueCallback();
    });
  }, concurrency);
  q.drain = function () { callback(results) };
  q.push(hosts);
};

//
// parse https response headers
//
exports.headersHttps = function(hosts, concurrency, callback) {
  var results = [];
  var q = async.queue(function (host, queueCallback) { 
    var req = https.request({'host': host}, function(res) {
      res.on('end', function() {
        if (res.headers.location) {
          var hostname = url.parse(res.headers.location)['hostname'];
          // we dont want an ip
          if (hostname && hostname.match(/[a-zA-Z]+/)) { 
            results.push( { ip: host,
                            name: hostname,
                            src: 'headers-https'
                          });
          }
        }
        queueCallback();
      });
    });
    req.end();
    req.on('error', function() {
      queueCallback();
    });
  }, concurrency);
  q.drain = function () { callback(results) };
  q.push(hosts);
};

//
// grab names from serversniff.net
//
exports.serversniff = function(hosts, concurrency, callback) {
  var results = [];
  var q = async.queue(function (host, queueCallback) {
    var message = '';    
    var options = {
      hostname: 'serversniff.net',
      path: '/hip-' + host
    };
    var req = http.request(options, function(res) {
      res.on('data', function(chunk) {
        message += chunk;
      });
      res.on('end', function() {
        var htmlTable = message.match(/<table>[\w\W]*?<\/table>/m);
        if (htmlTable) {
          results[host] = [];
          var rePattern = /<b>\s([a-z0-9\.\-]*)\s<\/b>/gi;
          // TODO: fix to use capture group
          var hostnames = htmlTable[0].match(rePattern); 
        }
        if (hostnames) {
          hostnames.forEach(function(h){
            var name = h.match(/<b>\s([\w\W]*)\s<\/b>/i);
            results.push({ip:host, name:name[1], src: 'server-snifff'});
          });
        }
        queueCallback();
      });
    });
    req.end();
    req.on('error', function() {
      queueCallback();
    });
  }, concurrency);
  q.drain = function () { callback(results) };
  q.push(hosts);
};

//
// Only return results that pass FCrDNS
//
exports.fcrdns = function(results, concurrency, callback) {
  var cleanResults = [];
  var q = async.queue(function (record, queueCallback) {
    dns.resolve4(record.name, function (err, addresses) {
      if (err) {
        queueCallback();
      }
      else {
        cleanResults.push( { ip: addresses[0],
                             name: record.name,
                             src: record.src
                           });
        queueCallback();
      }
    });     
  }, concurrency);
  q.drain = function () { callback(cleanResults) };
  q.push(results);
};
