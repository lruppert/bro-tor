##! The list of tor IPs is populated at startup from a file on disk, but
##! is re-read automatically at run-time if modified. Any traffic from a
##! local IP connecting to a known Tor server raises a notice.

@load base/frameworks/notice

module Tor;

export {
	redef enum Notice::Type += {
		Tor_Host
	};

	## The logging stream identifier, which tracks activity
	## of tor hosts (those that are caught talking to a known tor server).
	redef enum Log::ID += { HOSTS_LOG };

	## Record type which contains column fields of tor hosts log.
	type Info: record {
		## The timestamp at which activity of a tor host was detected.
		ts:   time &log;
		## The tor host's IP address.
		host: addr &log;
	};

	## The name of the file on disk which contains a list of IP addresses
	## and port numbers of tor bridges. Read at startup and upon 
	## modification.
	const hostlist_filename: string &redef;

	## Descriptive handle to associate with the *name* field of
	## :bro:see:`Input::TableDescription`.
	const input_handle: string = "tor-hostlist" &redef;

	## Interval for which activity of a host previously reported via
	## :bro:see:`Tor::check_host` can be ignored.  i.e. the event will be
	## raised at most once per this interval of time.
	const check_interval: interval = 1day &redef;

	## Set of IPs that are Tor nodes.  Populated from
	## :bro:see:`Tor::hostlist_filename`.
	global hostlist: set[addr];

	## Whether the input framework has finished reading
	## :bro:see:`Tor::hostlist_filename`.
	global hostlist_ready: bool = F;

	## Raised when activity for a host can be
	## checked against :bro:see:`Tor::hostlist`.
	global check_host: event(host: addr, cid: conn_id, uid: string);

	## An event that can be handled to access the :bro:type:`Tor::Info`
	## record as it is sent on to the logging framework.
	global log_tor_hosts: event(rec: Info);
}

event bro_init()
	{
	Log::create_stream(Tor::HOSTS_LOG,
	                   [$columns=Info, $ev=log_tor_hosts]);
	}
