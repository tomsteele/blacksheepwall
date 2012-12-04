var async = require('async');
var dns = require('dns');
var tls = require('tls');
var https = require('https');
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
       return;
      }
      results[addresses[0]] = lookup;
      queueCallback();
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
        return;
      }
      results[host] = domains;
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
// Bing query for vhosts
//
function bing(hosts, concurrency, callback) {
  var results = {};
  var q = async.queue(function (host, queueCallback) {
    results[host] = [];
    count = 50;
    offset = 0;
    message = '';
    var params = '?Query=%27ip:' + host + '%27' +
                 '&$top=' + count +   
                 '&$skip=' + offset + 
                 '&Adult=%27Off%27&$format=json';
    var options = {
      hostname: 'api.datamarket.azure.com',
      port: 443,
      path: '/Data.ashx/Bing/SearchWeb/v1/Web' + params,
      auth: bingKey + ':' + bingKey,
      method: 'GET'
    };
    var req = https.request(options, function(res) {
      res.on('data', function(chunk) {
        message += chunk;
      });      
      res.on('end', function() {
        var urls = JSON.parse(message).d.results;
        for (var i = 0; i < urls.length; i++) {
          results[host].push(url.parse(urls[i].Url)['hostname']);
        }
        message = '';
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

exports.dictionary = dictionary;
exports.reverse = reverse;
exports.cert = cert;
exports.bing = bing;
