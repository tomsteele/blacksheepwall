blacksheepwall
===

blacksheepwall is a hostname reconnaissance tool written in node. 

## Usage ##

    Usage: blacksheepwall [options] <ip file>

    Options:

    -h, --help               output usage information
    -V, --version            output the version number
    -c, --concurrency <int>  limit amount of asynchronous requests
    -d, --dictionary <file>  hostname guessing using a one host per line dictionary
    -t, --target <domain>    domain to use
    -r, --reverse            reverse name lookup
    -s, --ssl                grab names from ssl certificates
    -b, --bing               search bing for vhosts
    -w, --web                grab names from DNS websites (i.e., robtex, serversniff)
    -f, --fcrdns             perform forward confirmed rDNS and return compliant names
    --headers                parse http and https response headers for hostnames
    --csv                    output to csv
    --clean                  ouput clean data
    --json                   output a json object


## Contributors ##
Developed with care by Tom Steele (tom@huptwo34.com) and Jason Doyle
