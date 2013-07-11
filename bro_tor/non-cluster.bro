##! Load all the module scripts for use in a standalone environment.
##! Also works for environments where the master opens the input framework
##! and then won't share the data with any of the nodes, no matter how much
##! they beg and plead, forcing them to make all kinds of ignorant and wrong
##! decisions until the author finally hacks out the clustering support in a
##! vicious yet compassionate act of desperation.

@load ./main
@load ./read_hostlist
@load ./monitor
@load ./check
