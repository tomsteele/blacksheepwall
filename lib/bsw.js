var async = require('async');
var dns = require('dns');
var tls = require('tls');


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
    cleartextStream.on('error', queueCallback());
    cleartextStream.on('data', queueCallback());
    cleartextStream.on('end', queueCallback());
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
