brilter
=======

A filtering software bridge.

In short, my ISP provides native IPv6, but despite the CPE answering DHCPv6-PD requests, the CPE OS refuses to route any packets on the delegated prefix.  Rather than continue to fight with it and/or give up on having native IPv6 connectivity for the near future, I've decided to bridge my LAN to the IPv6 DMZ, passing only IPv6 packets and prohibiting any non-local inbound connections to things other than SSH.

Unfortunately, this works pretty poorly with the bridging and firewalling built into FreeBSD already.  It's impossible for PF to block things like ARP going across a bridge, seemingly, and the reality is that I'm much more of a programmer than an administrator, and so I find it easier to get my head around writing code than concocting rulesets.

With any luck, I'll actually see this project through, and perhaps try to generalize it into something useful to other people, or for other purposes.  It seems like a useful playground in addition to solving an immediate problem, which is how all of my projects which I most enjoy have begun.

# Errata

The version currently checked in uses `pcap-filter(7)` for filtering decisions, which is demonstrably-worse than the previous hand-rolled code.  Specifically, `pcap-filter(7)` as of 2014 still can't handle accessing TCP protocol fields in IPv6 packets, so we can't block inbound SYNs anymore.  This is ghastly and must change, but I think it's unlikely to.  A different filtering mechanism will be provided soon that's more flexible than the hand-rolled code but slightly more this-century than `libpcap` provides.  Maybe.  Until then, it's perhaps a more interesting playground for people who want to do layer 2 filtering on a software bridge with a familiar and familiarly-limited filter language.

# Usage

> ```brilter [-d] lan-interface wan-interface```

XXX This needs updated for the new Lua setup.

That is, `brilter` can be run as a daemon or not, by specifying the `-d` flag.  It needs two interfaces that it can use through `netmap(4)` (whether physical interfaces, VALE switches, pipes, etc.), one of which has LAN connectivity and one of which has WAN/DMZ connectivity.

While `brilter` is running, it will selectively bridge packets between `lan-interface` and `wan-interface`.  It allows link-local traffic and multicast traffic to pass unimpeded in both directions, so DHCPv6 and other local services should work as expected.

Traffic with the outside world is passed according to more restrictive, though still quite trivial, tests.  ICMPv6 is allowed unconditionally, but only TCP is allowed otherwise.  No UDP is allowed right now, which is mostly not a hardship for me, but may be for you.  It should be easy to write your own code if you really want UDP to work other than for link-local traffic.

As for TCP, while all outbound TCP traffic is allowed (that is, traffic from `lan-interface` *to* `wan-interface`), inbound traffic (i.e. traffic destined for your LAN from the WAN/DMZ) is filtered.  Packets which have `SYN` set and not `ACK` will not be forwarded unless their destination port is port 22.  That is, you can SSH from the WAN to a host on the LAN, but not create a TCP connection from a random host on the Internet to the LAN otherwise.

These rules are obviously more restrictive than most of what people want in a firewall, but luckily it's not a firewall.  It's a filtering bridge -- a dirty hack for a silly situation in which IPv6 cannot be used as intended, and the LAN segment must be provided at least partial Layer 2 connectivity with your DMZ.  This is preposterous, but at least with `brilter` it mostly sort of works, and prevents things too obscene to name.
