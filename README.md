blacksheepwall
===

blacksheepwall is a hostname reconnaissance tool written in node. 

## Installation ##
Once you have installed node, you can install globally using npm, this may require escalated privileges:

    npm install -g blacksheepwall

Alternatively, you can clone the repository, install the required modules using npm, and run from bin/:

    git clone https://github.com/tomsteele/blacksheepwall.git
    cd blacksheepwall && npm install
    bin/cmd.js
    
## Usage ##
    
    Usage: blacksheepwall [options] <ip range>

    Options:

      -h, --help               output usage information
      -V, --version            output the version number
      -c, --concurrency <int>  limit amount of asynchronous requests
      -d, --dictionary <file>  hostname guessing using a one host per line dictionary
      -t, --target <domain>    domain to use
      -r, --reverse            reverse name lookup
      -s, --ssl                grab names from ssl certificates
      -b, --bing               search bing for vhosts
      -k, --bingkey <apikey>   supply api key for bing searches
      -f, --fcrdns             perform forward confirmed rDNS and return compliant names
      --headers                parse http and https response headers for hostnames
      -i, --input <file>       input file containing ip addresses
      --csv                    output to csv
      --clean                  ouput clean data
      --json                   output a json object

## Contributors ##
Developed with care by Tom Steele (tom@huptwo34.com) and Jason Doyle
