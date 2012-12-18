var async = require('async');
var dns = require('dns');

//
// dictionary based lookup
//
function dictionary(domain, names, concurrency, callback) {
  var results = {};
  // if concurrency is less than or equal to 0 we set it to the max
  concurrency = (concurrency <= 0) ? names.length : concurrency;
 
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
  concurrency = (concurrency <= 0) ? hosts.length : concurrency;
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
  
exports.dictionary = dictionary;
exports.reverse = reverse;
