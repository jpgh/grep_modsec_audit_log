Grep apache modsec_audit.log. searches for a string or regexp in the log file
and displays all sections request (or required, options (-B, -C, -F, -H, -E))

usage: modsec_parse.py [-h] -f FILE [-B] [-C] [-F] [-H] [-E] [-r]
                       search_string

parse mod_security audit log

positional arguments:
  search_string

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  path to logfile
  -B, --request_headers
                        Print request headers
  -C, --request_body    Print request body
  -F, --response_headers
                        Print response headers
  -H, --trailer         Print audit log trailer
  -E, --int_resp_body   Print intended response body
  -r, --regexp          Find with regexp
