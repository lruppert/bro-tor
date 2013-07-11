##! Monitors for activity and raises an event to check whether the host is
##! connecting to Tor.

@load ./main

module Tor;

global checked_hosts: set[addr] &create_expire=Tor::check_interval;

function do_check(host: addr, c: connection)
	{
	if ( host in Tor::checked_hosts ) return;

	event Tor::check_host(host, c$id, c$uid);
	}

# Both sides are known to be active if a TCP handshake completed, so check them.
event connection_established(c: connection) &priority=5
	{
	if ( c$orig$state != TCP_ESTABLISHED ) return;
	if ( c$resp$state != TCP_ESTABLISHED ) return;

	do_check(c$id$orig_h, c);
## Eventually we'll get ambitious and identify local Tor servers too, but not
## today.
#	do_check(c$id$resp_h, c);
	}

