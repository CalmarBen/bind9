.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

.. highlight: console

.. iscman:: update-ipset
.. _man_update-ipset:

update-ipset.so - dynamically updates ipset from DNS queries
---------------------------------------------------------------

Synopsis
~~~~~~~~

:program:`plugin query` "update-ipset.so" [{ parameters }];

Description
~~~~~~~~~~~

:program:`update-ipset.so` is a query plugin module for :iscman:`named`, enabling
:iscman:`named` to automatically update some chosen ipset

This allows to provide a whitelist based security, not relaying on IP adresses only.
It is designed to handle situations when the network proxy cannot be used. This is typically
when some client software are ignoring the workstation and network proxy settings, and
despite this design flaw, we still want to use it.
Whitelist is the typical usage, however the real usage of course depends on what is the subsequent
usage of the set in the firewall rules.

Note that you need to be careful with the firewall rules and the name service reliability.
In particular, keep in mind that whitelisting an IP from a correct name, would also allow
any connection (supposing a firewall rule is relaying on it), by IP or even another name.
So we need to be careful by checking this:
* avoid CDN targets
* always prefer proxy Network Path when this is possible
* check some IPs by whois to check that the IP owner is legitimate

Example of configuration:

::

        plugin query "update-ipset.so" {
                # libipset 'safe' test for ipv4
                ipset safe {
                    sites  {
                        *.example.com.;
                        *.other-example.com.;
                    };
                    ttl 86400;
                };
                # libipset 'safev6' test for ipv6
                ipset safev6 {
                    sites {
                        *.example.com.;
                        *.other-example.com.;
                    };
                    ipv6;
                };
                # nft set for table filter inet in ipv4
                ipset entertainment {
                    sites {
                        *.example.com.;
                    };
                    ttl 3600;
                    nftable filter;
                    family inet;
                };
        };

Options
~~~~~~~

 ``ipset``
   Designates a new ipset mapping. The set must exist, and will not be created automatically.

 ``nftable``
   nftable name to update. Only valid and mandatory for nftables ip sets.

 ``family``
   Network family of the nftable to update. Only valid for nftables ipsets. Defaults to 'ip' if ipv6 option is absent, and defaults to 'ip6' if ipv6 option is present.
   Possible values are: 'ip', 'ip6', 'arp', 'bridge', 'netdev'

 ``sites``
   Contains a list of domain wildcard to match for this set. The site syntax must end with a dot ('.'), otherwise the configuration check will fail.

 ``ttl``
   Add the entry with given ttl in place of the default timeout for that set. The ttl is automatically handled by the kernel.
   Warning: this as no effect if the 'timeout' flag is not present in the nftables set. If the ttl is unspecified here, the timeout will be the nftables timeout value if persent, or otherwise the ttl of the response.

 ``ipv6``
   If specified, the target elements are ipv6, and will populated only if an AAAA address is found.
   Defaults to true if 'family' option equals to 'ip6'



See Also
~~~~~~~~

BIND 9 Administrator Reference Manual.
