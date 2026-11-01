# vscan-unvalidated-redirect-detector
Detects potential unvalidated redirect vulnerabilities. HTTP redirects are inspected, not followed silently: each hop is checked, a hop that stays inside the named target origin is followed and logged, and a hop that leaves that origin is reported as an open redirect finding and is not fetched. HTML responses are also parsed for redirect targets, and only targets whose parsed hostname is neither the target host nor a listed safe domain are reported. With --input-param, the tool sends a distinctive test value in that parameter and reports user input control only when the redirect destination matches the supplied value. A scan that cannot be completed, for example an unreachable target or an HTTP error response, exits non-zero instead of reporting a clean result. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-unvalidated-redirect-detector`

## Usage
`./vscan-unvalidated-redirect-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `--input-param`: Name of a URL parameter to test with a supplied test value for user input control of the redirect destination
- `--safe-domains`: Comma-separated list of extra hostnames treated as safe redirect targets, matched by parsed hostname (exact or true subdomain)
- `--method`: HTTP method to use, GET or POST (default GET)
- `--data`: Data to send with the request (for POST method, e.g., "param1=value1&param2=value2"); a value may itself contain = characters

## License
Copyright (c) ShadowStrikeHQ
