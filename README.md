brilter
=======

A filtering software bridge.

In short, my ISP provides native IPv6, but despite the CPE answering DHCPv6-PD requests, the CPE OS refuses to route any packets on the delegated prefix.  Rather than continue to fight with it and/or give up on having native IPv6 connectivity for the near future, I've decided to bridge my LAN to the IPv6 DMZ, passing only IPv6 packets and prohibiting any non-local inbound connections to things other than SSH.

Unfortunately, this works pretty poorly with the bridging and firewalling built into FreeBSD already.  It's impossible for PF to block things like ARP going across a bridge, seemingly, and the reality is that I'm much more of a programmer than an administrator, and so I find it easier to get my head around writing code than concocting rulesets.

With any luck, I'll actually see this project through, and perhaps try to generalize it into something useful to other people, or for other purposes.  It seems like a useful playground in addition to solving an immediate problem, which is how all of my projects which I most enjoy have begun.
