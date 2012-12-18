#!/usr/bin/env node
var fs = require('fs');
var program = require('commander');
var bsw = require('../lib/bsw');

//
// takes a file containing ip address until we write a ip address parser
// that will suck
//
program
  .version('0.0.1')
  .usage('[options] <ip file>')
  .option('-d, --dictionary <file>', 'hostname guessing using a one host per line dictionary')
  .option('-r, --reverse', 'reverse name lookup')
  .option('-c, --concurrency <int>', 'limit amount of asyncrounous requests')
  .option('-b, --bing', 'lookup hostnames on bing')
  .option('-o, --robtext', 'lookup hostnames on robtext')
  .option('-t, --target <domain>', 'domain to use')
  .parse(process.argv);

var concurrency = program.concurrency ? program.concurrency : -1;
var resultsDb = {};

if (program.dictionary) {
  if (!program.target) {
    croak('dictionary attack requires target domain');
  }
  var items = fs.readFileSync(program.dictionary).toString().split("\n");
  bsw.dictionary(program.target, items, concurrency, function(results) {
    console.log(results);
  });
}

if (program.reverse) {
  var ips = fs.readFileSync(program.args[0]).toString().split("\n");
  ips.pop();
  bsw.reverse(ips, concurrency, function(results) {
    console.log(results)
  });
}

//
// generic function to print and exit
//
function croak(errorMessage) {
  console.log(errorMessage);
  process.exit(1);
}
