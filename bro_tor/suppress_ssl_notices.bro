##! This suppresses SSL certificate warnings in the notice.log for connections
##! to known Tor servers. We want to know when people are clicking through the
##! Russians' "Paypall is same thing as Paypal credit card form" sites. We
##! don't, however, want that alarm to be lost in a cacophony of Tor servers
##! shouting "Squirrel!"

@load protocols/ssl/validate-certs

function suppress_tor_ssl_notice(n: Notice::Info): bool
{
    # Outbound
    if (n$src in Tor::hostlist)
        return T;
    # Inbound
    if (n$dst in Tor::hostlist)
        return T;

    return F;
}

hook Notice::policy(n: Notice::Info) &priority=3
	{
	if ( n$note==SSL::Invalid_Server_Cert && suppress_tor_ssl_notice(n) )
		break;
	}

