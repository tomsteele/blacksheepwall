#!/usr/bin/env node
// Copyright (c) 2012 Tom Steele, Jason Doyle
// See the file license.txt for copying permission
var fs = require('fs');
var https = require('https');
var dns = require('dns');
var program = require('commander');
var async = require('async');
var bsw = require('../');
var _ = require('lodash');
var netmask = require('netmask');
var winston = require('winston');

program
  .version('0.7.0')
  .usage('[options] <ip range>')
  .option('-c, --concurrency <int>', 'limit amount of concurrent requests')
  .option('-d, --dictionary <file>', 'hostname guessing using a one host per line dictionary')
  .option('-t, --target <domain>', 'target domain to use for domain based operations')
  .option('-r, --reverse', 'reverse name lookup')
  .option('-s, --ssl', 'grab names from ssl certificates')
  .option('-b, --bing', 'search bing for vhosts')
  .option('-k, --bingkey <apikey>', 'supply api key for bing searches')
  .option('-y, --yandex <apiurl>', 'search yandex using rhost operator, requires API key')
  .option('-f, --fcrdns', 'perform forward confirmed rDNS on all names')
  .option('--headers', 'parse http and https response headers for hostnames')
  .option('-i, --input <file>', 'input file containing ip addresses')
  .option('--csv', 'output to csv')
  .option('--clean', 'ouput clean data')
  .option('--json', 'output a json object')
  .parse(process.argv);

// Catch any exceptions and plead with the client to notify us
process.on('uncaughtException', function(err) {
  winston.error('Uncaught exception: Please notify the developers.');
  winston.error(err.message);
  process.exit(1);
});

// BSW object options creation
var bswOptions = {};
bswOptions.concurrency = program.concurrency ? program.concurrency : 1000;
bswOptions.hosts = [];
// Ensure client specified at least one item of data for attacks
if (!program.args[0] && !program.dictionary && !program.input && !program.yandex) {
  croak('No ip range or domain level searches provided');
}
if (program.dictionary && !program.target) {
  croak('Dictionary attack requires target domain set with --target');
}
// Ensure client provided target for yandex search
if (program.yandex && !program.target) {
  croak('Yandex search requires target domain set with --target');
}
// Read the domain file and set target domain
if (program.dictionary) {
  if (!fs.existsSync(program.dictionary)) {
    croak('Invalid dictionary file location');
  }
  bswOptions.names = fs.readFileSync(program.dictionary, {encoding: 'utf8'}).trimRight().split("\n");
  bswOptions.names = bswOptions.names.map(function(x) { return x.trimRight(); });
}
if (program.target) {
  bswOptions.domain = program.target;
}
// Parse a netblock as provided and build host list
if (program.args[0]) {
  var block = new netmask.Netmask(program.args[0]);
  var start = netmask.ip2long(block.first);
  var end = netmask.ip2long(block.last);
  while (start <= end) {
    bswOptions.hosts.push(netmask.long2ip(start));
    start++;
  }
  // An input file was provided and a netblock was given
  if (program.input) {
   console.log('[!] ignoring input file');
  }
// Or build the list of hosts file a file
} else if (program.input) {
  if (!fs.existsSync(program.input)) {
    croak('Invalid input file location');
  }
  bswOptions.hosts = fs.readFileSync(program.input, {encoding: 'utf8'}).trimRight().split("\n");
  // on windows we need to remove the '\r'
  bswOptions.hosts = bswOptions.hosts.map(function(x) { return x.trimRight(); });
}
var b = bsw(bswOptions);

// Task list for async.parallel
var tasks = [];
// Build task list
if (program.dictionary) {
  tasks.push(function(cb) {
    // Check for wildcard domain. If this domain exists, stop, this target is too awesome to attack 
    dns.resolve4('youmustconstructadditionalpylons.' + program.target, function (err, addresses) {
      if (addresses) {
        winston.error('Skipping dictionary lookups for wildcard domain *.' + program.target);
      } else {
        b.dictionary(cb);
      }
    });
  });
}
if (program.reverse) {
  tasks.push(function(cb) {
    b.reverse(cb);
  });
}
if (program.ssl) {
  tasks.push(function(cb) {
    b.ssl(cb);
  });
}
if (program.yandex) {
  tasks.push(function(cb) {
    b.yandex(program.yandex, cb);
  });
}
if (program.bing) {
  // User provided a Bing API key
  if (program.bingkey) {
    tasks.push(function(cb) {
      // Detect which API path the key is valid for
      var apiPaths = ['/Data.ashx/Bing/Search/v1/Web', '/Data.ashx/Bing/SearchWeb/v1/Web'];
      apiDetect(apiPaths);
      function apiDetect(apiPaths) {
        var options = {
          host: 'api.datamarket.azure.com',
          auth: program.bingkey + ':' + program.bingkey
        };
        // Sample query to detect correct path
        options.path = apiPaths[0] + "?Query=%27I<3BSW%27";
        // If apiPaths is 0, we didn't find a valid path
        // Show error and skip
        if (!apiPaths.length) {
          winston.error('Invalid Bing API key');
          cb();
        } else {
          // Attempt to call the path using the sample query
          // if 200, the path is valid, use it for the host queries
          https.get(options, function(res) {
            if (res.statusCode === 200) {
              b.bingApi(options, cb);
            }
            // Shift the previous path off the array and attempt the next one
            else {
              apiPaths.shift();
              apiDetect(apiPaths);
            }
          });
        }
      }
    });
  } else {
    // No key provided. Do a HTML based lookup
    tasks.push(function(cb) {
      b.bing(cb);
    });
  }
}
if (program.headers) {
  tasks.push(function(cb) {
    b.headers(cb);
  });
}

// Output start time and run
var now = new Date();
console.error('bsw started at', now);
async.parallel(tasks, function(err) {
  if (err) {
    console.log(err);
  } else {
    process.nextTick(function() {
      now = new Date();
      b.results = _.flatten(b.results);
      if (program.fcrdns && b.results.length > 0) {
        b.fcrdns(function() {
          console.error('bsw finished at', now);
          output(b.results);
        });
      } else {
        console.error('bsw finished at', now);
        output(b.results);
      }
    });
  }
});

// Handle output
function output(results) {
  var sorted = {};
  if (program.csv) {
    outcsv(results);
  } else if (program.clean) {
    sort();
    outclean(sorted);
  } else if (program.json) {
    sort();
    outjson(sorted);
  } else {
    results.forEach(function(record) {
      if (record.ip) {
        console.log('name:', record.name, 'ip:', record.ip, 'method:', record.src);
      }
    });
  }
  process.exit(0);

  function sort() {
    results.forEach(function(record) {
      // When we flatten the arrays they well leave an empty object if no results
      if (record.ip) {
        if (sorted[record.ip]) {
          sorted[record.ip].push(record.name);
        } else {
          sorted[record.ip] = [record.name];
        }
      }
    });
    for (var k in sorted) {
      sorted[k] = _.uniq(sorted[k]);
    }
  }
}

function outcsv(results) {
  results.forEach(function(record) {
    if (record.ip) {
      console.log(record.name + ',' + record.ip + ',' + record.src);
    }
  });
}

function outjson(sorted) {
  var jsonout= [];
  for (var k in sorted) {
    jsonout.push({ "ip": k, "names": sorted[k] });
  }
  console.log(JSON.stringify(jsonout, null, " "));
}

function outclean(sorted) {
  for (var k in sorted) {
    console.log(k + ':');
    sorted[k].forEach(function(element) {
      console.log(' ', element);
    });
  }
}
// Generic function to print and exit
function croak(errorMessage) {
  console.log(errorMessage);
  process.exit(1);
}
