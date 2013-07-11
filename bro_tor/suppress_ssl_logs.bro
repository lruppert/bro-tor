##! This suppresses logging of the Tor random certificates in the ssl.log
##! file. Nothing like having your log file spammed with Tor certificates
##! because some clever cat has decided that running bittorrent over Tor
##! is some kind of new sugary awesomeness he can't go half a day without.

module Tor;

function suppress_tor_ssl_logging(c: SSL::Info): bool
{
    # Outbound
    if (c$id$orig_h in hostlist)
        return T;
    # Inbound
    if (c$id$resp_h in hostlist)
        return T;

    return F;
}

event bro_init()
{
    Log::remove_default_filter(SSL::LOG);
    Log::add_filter(SSL::LOG, [$name = "ssl",
                                $path = "ssl",
                                $pred(rec: SSL::Info) = {
        return (!suppress_tor_ssl_logging(rec));
    }]);
}

