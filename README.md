# dnsstat

**libpcap-based tool for analyzing DNS performance**

Copyright 2017, 2019, 2021 by Alexander Koch


## About

_dnsstat_ has been created in desperate need for a tool for debugging DNS
issues on a broadband connection at home. Surfing the web felt slow and
stuttery but issuing test queries using [dig](https://linux.die.net/man/1/dig)
never yielded any lost query, so the author decided to capture all DNS traffic
and perform an offline analysis.

_dnsstat_ implements this analysis, enabling its user to avoid manual
accounting using [Wireshark](https://www.wireshark.org) and the-like.

### Limitations

Currently _dnsstat_ only recognizes DNS packets matching the following criteria:
* Layer 1-2: Ethernet
* Layer 3: IPv4 or IPv6
* single DNS query/response per packet


## Building

Make sure you have the following requirements installed:
* cmake
* libpcap (tested with 1.8.1)

The code is supplied as a *CMake* project so either use your favorite IDE or
compile manually:
```
$ cmake .
$ make
```

There currently is no installation mechanism, the binary is located in the build
directory.


## Usage

Run the binary with a pcap file as argument:
```
$ ./dnsstat /path/to/trace.pcap
Queries
    sent:           309
    answered:       307
    lost:             2 (0.01%)
Delay
    min:           0.11 ms
    avg:          66.89 ms
    max:        1052.54 ms
    stdev:       206.59 ms
```
Help is available using `-h`.

A packet trace for analysis can be obtained using `tcpdump`:
```
$ tcpdump -i eth0 -w trace.pcap 'udp port 53'
```


## Contributing

This project is provided this _as-is_, in hope that it might be of any use for
someone who needs to debug DNS issues or collect DNS performance metrics.

Pull requests for improvements or bug fixes are greatly appreciated.


## License

This work is published under the terms of the MIT License, see file `LICENSE`.

