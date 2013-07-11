##! Reads a simple list of IP addresses and ports from a file on disk.
##! The format of the file is expected to match the following:
##! tor_host
##! 192.168.1.1
##! Copied and modified from jsiwek's bro_vetting module

@load ./main
@load base/frameworks/input

module Tor;

type Idx: record {
	tor_host: addr;
};

event bro_init() &priority=5
	{
	Input::add_table([$source=hostlist_filename, $mode=Input::REREAD,
	                  $name=input_handle, $idx=Idx,
	                  $destination=hostlist]);
	}

event Input::update_finished(name: string, source: string) &priority=5
	{
	if ( name == input_handle )
		hostlist_ready = T;
	}

#event Input::end_of_data(name: string, source: string) &priority=5
#	{
#	if ( name == input_handle )
#		hostlist_ready = T;
#	}

