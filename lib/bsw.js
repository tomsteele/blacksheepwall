var async = require('async');
var dns = require('dns');
var tls = require('tls');
var https = require('https');
var http = require('http');
var url = require('url');
var bingKey = '<BING API KEY HERE>';

//
// dictionary based lookup
//
function dictionary(domain, names, concurrency, callback) {
  var results = {};
  var q = async.queue(function (lookup, queueCallback) {
    lookup = lookup + '.' + domain;
    dns.resolve4(lookup, function (err, addresses) {
      if (err) {
       queueCallback();
      }
      else {
        results[addresses[0]] = lookup;
        queueCallback();
      }
    });
  }, concurrency);
  q.drain = done;
  q.push(names);

  // generic defintiion for the q.drain
  function done() {
    callback(results);
  }
}

//
// reverse ip lookup
//
function reverse(hosts, concurrency, callback) {
  var results = {};
  var q = async.queue(function (host, queueCallback) {
    dns.reverse(host, function (err, domains) {
      if (err) {
        queueCallback();
      }
      else {
        results[host] = domains;
        queueCallback();
      }
    });
  }, concurrency);
  q.drain = done;
  q.push(hosts);
  
  function done() { 
    callback(results);
  }
}
  
//
// grabs hostnames from ssl certificates
//
function cert(hosts, concurrency, callback) {
  var results = {};
  var q = async.queue(function (host, queueCallback) {
    var cleartextStream = tls.connect(443, host, function () {
      var cert = cleartextStream.getPeerCertificate();
      var cn = cert['subject']['CN'];
      var sns = cert['subjectalname'];
      if (cn) {
        results[host] = [cn];
      }
      if (sns) {
        results[host].push(sns);
      }
     queueCallback();
    });
    cleartextStream.on('error', queueCallback);
    cleartextStream.on('data', queueCallback);
    cleartextStream.on('end', queueCallback);
  }, concurrency);
  q.drain = done;
  q.push(hosts);
  
  function done() {
    callback(results);
  }
}

//
// bing query for vhosts
//
function bing(hosts, concurrency, callback) {
  var results = {};
  var q = async.queue(function (host, queueCallback) {
    var count = 50;
    var offset = 0;
    var message = '';
    var params = '?Query=%27ip:' + host + '%27' +
                 '&$top=' + count +   
                 '&$skip=' + offset + 
                 '&Adult=%27Off%27&$format=json';
    var options = {
      hostname: 'api.datamarket.azure.com',
      path: '/Data.ashx/Bing/SearchWeb/v1/Web' + params,
      auth: bingKey + ':' + bingKey,
    };
    var req = https.request(options, function(res) {
      res.on('data', function(chunk) {
        message += chunk;
      });      

      res.on('end', function() {
        if (res.statusCode == 401) {
          console.log('invalid bing API key');
          process.exit(1);
        }
        var urls = JSON.parse(message).d.results;
        for (var i = 0; i < urls.length; i++) {
          if (results[host]) {
            results[host].push(url.parse(urls[i].Url)['hostname']);
          }
          else {
            results[host] = [url.parse(urls[i].Url)['hostname']];
          }
        }
        queueCallback();
      });
    });
    req.end();
    req.on('error', function(e) {
      queueCallback();
    });
  }, concurrency);
  q.drain = done;
  q.push(hosts);

  function done() {
    callback(results);
  }
}

//
// grab name records from robtex.com one c-network at a time
//
function robtex(hosts, concurrency, callback) {
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
  var results = {};
  var q = async.queue(function (cnet, queueCallback) {
    var message = '';    
    var options = {
      hostname: 'cnet.robtex.com',
      path: '/' + cnet + '.html',
    };
    var req = http.request(options, function(res) {
      res.on('data', function(chunk) {
        message += chunk;
      });
      res.on('end', function() {
        htmlRows = message.match(/<tr>[\w\W]*?<\/tr>/mg);
        for (var i = 0; i < htmlRows.length; i++) {
          var ipMatch = htmlRows[i].match(/ip\.robtex\.com\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\./);
          if (ipMatch) {
            var ip = ipMatch[1];
            for (var c = 0; c < hosts.length; c++) { // check if ip in scope
              if (ip == hosts[c]) {
                var hostname = htmlRows[i].match(/>([a-z0-9-\.]{2,}[a-z])<\/a>/i);
                if (hostname) {
                  if (results[ip]) {
                    results[ip].push(hostname[1]);
                  }
                  else {
                    results[ip] = [hostname[1]];
                  }
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
    req.on('error', function(e) {
      queueCallback();
    });
  }, concurrency);
  q.drain = done;
  q.push(cNetworks);

  function done () {
    callback(results);
  }
}

//
// parse http response headers
// TODO: build regex to match all header params
//
function headersHttp(hosts, concurrency, callback) {
  var results = {};
  var q = async.queue(function (host, queueCallback) {
    var req = http.request({'host': host}, function(res) {
      res.on('end', function() {
        if (res.headers.location) {
          var hostname = url.parse(res.headers.location)['hostname'];
          if (hostname && hostname.match(/[a-zA-Z]+/)) { // we don't want an ip
            results[host] = [hostname];
          }
        }
        queueCallback();
      });
    });
    req.end();
    req.on('error', function(e) {
      queueCallback();
    });
  }, concurrency);
  q.drain = done;
  q.push(hosts);

  function done() {
    callback(results);
  }
}

//
// parse https response headers
//
function headersHttps(hosts, concurrency, callback) {
  var results = {};
  var q = async.queue(function (host, queueCallback) { 
    var req = https.request({'host': host}, function(res) {
      res.on('end', function() {
        if (res.headers.location) {
          var hostname = url.parse(res.headers.location)['hostname'];
          if (hostname && hostname.match(/[a-zA-Z]+/)) { // we don't want an ip
            results[host] = [hostname];
          }
        }
        queueCallback();
      });
    });
    req.end();
    req.on('error', function(e) {
      queueCallback();
    });
  }, concurrency);
  q.drain = done;
  q.push(hosts);

  function done() {
    callback(results);
  }
}

//
// grab names from serversniff.net
//
function serversniff(hosts, concurrency, callback) {
  var results = {};
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
        htmlTable = message.match(/<table>[\w\W]*?<\/table>/m);
        if (htmlTable) {
          results[host] = [];
          var rePattern = /<b>\s([a-z0-9\.\-]*)\s<\/b>/gi;
          var hostnames = htmlTable[0].match(rePattern); // TODO: fix to use capture group
        }
        for (var h = 0; h < hostnames.length; h++) {
          var hostname = hostnames[h].match(/<b>\s([\w\W]*)\s<\/b>/i);
          results[host].push(hostname[1]);
        }
        queueCallback();
      });
    });
    req.end();
    req.on('error', function(e) {
      console.log(e);
      queueCallback();
    });
  }, concurrency);
  q.drain = done;
  q.push(hosts);

  function done () {
    callback(results);
  }
}

//
// Only return results that pass FCrDNS
//
function fcrdns(hosts, results, concurrency, callback) {
  fcResults = {}; // stores compliant ip => [names]
  var q = async.queue(function (hostname, queueCallback) {
    dns.resolve4(hostname, function (err, addresses) {
      if (err) {
        queueCallback();
      }
      else {
        for (var c = 0; c < hosts.length; c++) {
          if (hosts[c] == addresses[0]) {
            if (fcResults[addresses[0]]) {
              fcResults[addresses[0]].push(hostname);
            }
            else {
              fcResults[addresses[0]] = [hostname];
            }
          }      
        }
        queueCallback();
      }
    });     
  }, concurrency);
  q.drain = done;
  for (var i = 0; i < hosts.length; i++) {
    if (results[hosts[i]]) {
      q.push(results[hosts[i]]);
    }
  }

  function done() {
    callback(fcResults);
  }
}

exports.dictionary = dictionary;
exports.reverse = reverse;
exports.cert = cert;
exports.bing = bing;
exports.robtex = robtex;
exports.serversniff = serversniff;
exports.headersHttp = headersHttp;
exports.headersHttps = headersHttps;
exports.fcrdns = fcrdns;
