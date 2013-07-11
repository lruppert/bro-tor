##! This is based on jsiwek's code, except that I've beaten it so many times
##! with the ugly stick that now it doesn't work.

@load ./main

@load base/frameworks/cluster

redef Cluster::worker2manager_events += /^Tor::check_host$/;

@if ( Cluster::local_node_type() == Cluster::MANAGER )
@load ./read_hostlist
@load ./check
@endif

@if ( Cluster::local_node_type() == Cluster::WORKER )
@load ./monitor
@endif
