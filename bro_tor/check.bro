##! Handles the checking of whether a host is connecting to Tor.  If it is,
##! the activity is logged and a notice is raised.

@load base/frameworks/notice
@load base/frameworks/software

@load ./main

module Tor;
 
export {
      redef enum Software::Type += {
              ## Identifier for Tor clients in the software framework.
              SERVER,
              ## Identifier for Tor servers in the software framework.
              CLIENT,
      };
}

global logged_hosts: set[addr] &create_expire=Tor::check_interval;

event Tor::re_check_host(host: addr, cid: conn_id, uid: string)
	{
	if ( ! Tor::hostlist_ready )
		Reporter::fatal(fmt("Failed to read tor hostlist from %s",
		                    Tor::hostlist_filename));
	else
		event check_host(host, cid, uid);
	}
#
# We check the following:
# if resp_host is in the tor hostlist and the source host is not in 
# the logged_hosts, we log a notice and save the host in the log.
#
# Eventually we may want to log this activity in the tunnel log or the
# software log, but for now we can get away with just dumping it to its
# own file.
#
event Tor::check_host(host: addr, cid: conn_id, uid: string) &priority=5
	{
	if ( ! Tor::hostlist_ready )
		schedule 15sec { Tor::re_check_host(host, cid, uid) };
	else if ( cid$resp_h in Tor::hostlist )
		{
		local msg = fmt("Tor usage detected from %s", host);
		NOTICE([$note=Tor_Host, $msg=msg, $uid=uid, $id=cid,
		        $identifier=fmt("%s", host),
		        $suppress_for=Tor::check_interval]);
		Software::found(cid, [$unparsed_version="detected via ssl",$host=host, $software_type=CLIENT]);
		
	        if ( host !in logged_hosts )
		   {
		   add logged_hosts[host];
		   Log::write(Tor::HOSTS_LOG, [$ts=network_time(), $host=host]);
		   }
		}
	}
