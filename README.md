# dnsstat

**libpcap-based tool for analyzing DNS performance**

Copyright 2017 by Alexander Koch


## About

_debugdns_ was created in desperate need for having a tool to debug DNS problems
on a home-broadband connection. Surfing the web felt slow and stuttery, but
issuing test-queries using _dig_ never yielded any lost query, so I decided to
capture all DNS traffic and do offline analysis.

Fiddling around with Wireshark traces then felt just wrong at some point. Never
do analysis on large datasets by hand that a machine can do much better for you
instead.


## Building

Make sure you have the following requirements installed:
* libpcap (tested with 1.8.1)

The code is supplied as a *CMake* project so either use your favorite IDE or
compile manually (example builds inside source tree):
```
$ cmake .
$ make
```

There currently is no installation mechanism, the binary is located in the build
directory.


## Usage

Just run the binary with a pcap file as argument:
```
$ ./dnsstat /path/to/trace.pcap
no. queries: 309
no. replies: 307
no. lost:    2 (0.01%)
min. delay:  0.11 ms
avg. delay:  66.89 ms
max. delay:  1052.54 ms
std. dev.:   206.59 ms
```
Help is available using `-h`.


## Contributing

I provide this _as-is_, in hope that it might be of any use for someone who
needs to debug DNS problems or collect DNS performance metrics.

Pull requests for improvements or bug fixes are always welcome.


## License

This work is published under the terms of the MIT License, see file `LICENSE`.

