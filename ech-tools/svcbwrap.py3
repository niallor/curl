#!/usr/bin/python3

import os
import sys
import dns.resolver
import dns.rcode
import pprint

from dns import __version__ as dnspython_version

from collections import namedtuple
Service = namedtuple('Service', 'scheme, hostname, port')
Response = namedtuple('Response', 'qname, qtype, rcode, answer')

Supported_Schemes = ('https', 'http')
Supported_Applications = ('curl',)

pp = pprint.PrettyPrinter(stream=sys.stderr, indent=4)

def warn(*objects, sep=' ', end='\n', file=sys.stderr, flush=False):
    print(*objects, sep=' ', end='\n', file=file, flush=False)

def run_query(qname, qtype):
    try:
        answer = dns.resolver.resolve(
            qname, qtype, raise_on_no_answer=False)
        rcode = answer.response.rcode()
    except dns.resolver.NXDOMAIN:
        # NXDOMAIN might simply indicate absence of data for tagleaf
        answer = None
        rcode = dns.rcode.NXDOMAIN
        # No need to handle any other exceptions; failure is ideal
    return Response(qname, qtype, rcode, answer)

def origin_from_url(url, scheme='https'):
    # Service = namedtuple('Service', 'scheme, hostname, port')

    if url.scheme:
        scheme = url.scheme
    port = url.port
    if port:
        hostname = url.netloc.rsplit(':', 1)[0]
    else:
        hostname = url.netloc
    return Service(scheme.lower(), hostname.lower(), port)

def get_arguments():
    import argparse
    from urllib.parse import urlparse

    parser = argparse.ArgumentParser(
        fromfile_prefix_chars='@',
        epilog=' ',
        description=("Prepare command line to invoke application "
                     "with SVCB parameters as options"))

    parser.add_argument('application',
                        help='application program (file name or full path)')

    parser.add_argument('url',
                        type=urlparse, # not just a string
                        help='URL for application to visit')

    parser.add_argument('-4', dest='ipv4_only',
                    default=False, action='store_true',
                    help='resolve addresses to IPv4 only')

    parser.add_argument('-6', dest='ipv6_only',
                        default=False, action='store_true',
                        help='resolve addresses to IPv6 only')

    parser.add_argument('-d', '--debug', dest='debugging',
                        default=False, action='store_true',
                        help='enable debugging output')

    parser.add_argument('-n', '--dry-run', dest='dry',
                        default=False, action='store_true',
                        help='instead of running the application, '
                        'show command which will be used to run it.'
                        )

    parser.add_argument('-r', '--resolver',
                        default=[], action='append',
                        help='address of DNS resolver to use')

    parser.add_argument('-p', '--passthrough',
                        action='append', dest='passthrough', default=[],
                        help=
                        'encapsulate option to be passed to application; '
                        'may be repeated to pass additional options. '
                        'A simple option may be specified either '
                        "as \"-p=--option\" "
                        "or else as \"-p '--option '\" (note trailing space). "
                        'An option with a value may be specified as '
                        "\"-p '--option value'\"."
                        )

    # Process command line
    return parser.parse_args()      # Apply parser

def svcbresolve(origin):
    # assert origin.scheme in ('https', 'http')
    assert origin.scheme in Supported_Schemes

    service = origin
    ready = False
    qname = service.hostname
    port = service.port
    state = { 'name': qname }

    while not ready:
        if service == origin:   # Initial resolution pass
            if service.scheme == 'http':
                qtype = 'HTTPS'
                default_port = 443
                state['scheme'] = 'https'
                if port not in (None, 80, 443):
                    qname = '_' + str(port) + '._https.' + qname
                    state['port'] = port
            if service.scheme == 'https':
                qtype = 'HTTPS'
                default_port = 443
                state['scheme'] = 'https'
                if port not in (None, 443):
                    qname = '_' + str(port) + '._https.' + qname
                    state['port'] = port
            if not port:
                state['port'] = default_port

            queries = ((service.hostname, 'A'),
                       (service.hostname, 'AAAA'),
                       # svcbtype last, so address hints can over-ride
                       (qname, qtype))

            
        else:                   # Iterative resolution pass(es)
            # advance state
            for tag in ('ipv6_addr', 'ipv4_addr'):
                if tag in state:
                    del state[tag]

            queries = ((service.hostname, 'A'),
                       (service.hostname, 'AAAA'),
                       # svcbtype last, so address hints can over-ride
                       (service.hostname, qtype))

        assert(queries)

        fetched = list(map(lambda x: run_query(x[0], x[1]), queries))
        for item in fetched:
            assert item.rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
            
            if item.qtype in ('A', 'AAAA'):
                if not item.answer.rrset:
                    continue

                addresses = list(
                    map(lambda x: str(x), item.answer.rrset.items))
                if args.debugging:
                    warn('  addresses: ', addresses)
                tag = {'AAAA': 'ipv6_addr', 'A': 'ipv4_addr'}[item.qtype]
                state[tag] = addresses

            elif item.qtype in ('HTTPS', 'SVCB'):
                if (not item.answer) or (not item.answer.rrset):
                    ready = True # no target to chase
                    state['scheme'] = origin.scheme # no upgrade needed
                    continue

                binding = item.answer.rrset.processing_order()[0]
                priority = binding.priority
                target = binding.target.to_text()

                # TODO: Heed ALPN ID, if any

                if priority == 0:
                    # Alias mode
                    assert target not in ('.', service.hostname,
                                          service.hostname + '.')
                    service = Service(state['scheme'], target, state['port'])
                    done = False

                else:
                    # Service mode
                    if target in ('.', service.hostname,
                                  service.hostname + '.'):
                        ready = True

                    if args.debugging:
                        warn('  parameters:')
                    
                    for pkey in binding.params:

                        if pkey > 6:
                            warn('    unrecognized parameter:',
                                 str(pkey),
                                 '-- skipping')

                            break # keys must be in ascending order
                        
                        tag = (
                            'mandatory',
                            'alpn', 'no_default_alpn', 'port',
                            'ipv4_addr', 'echconfig', 'ipv6_addr',
                        )[pkey]

                        if pkey in (4, 6):
                            addresses = binding.params[pkey].addresses
                            if args.debugging:
                                digit = str(pkey)
                                warn('    IPv' + digit + ' hints:',
                                     addresses)
                            if (tag not in state):
                                state[tag] = addresses
                                if args.debugging:
                                    warn('      no IPv' + digit +
                                         ' addresses yet: using hints')
                            elif args.debugging:
                                warn('      IPv' + digit +
                                      'addresses found: ignoring hints')

                        else: # pkey in (0, 1, 2, 3, 5)
                            state[tag] = (
                                binding.params[pkey].to_text().strip('"'))
                            if args.debugging:
                                warn('    {:<11} {}'.format(
                                    tag + ':', state[tag]))

            # next item in fetched
        # loop while not ready

    return state

# -- Now to business ...

args = get_arguments()

if dnspython_version < '2.2':
    warn('Found dnspython version', dnspython_version)
    warn('For SVCB support, version 2.2 or later is required')
    warn('')
    warn('If no suitable version is available using pip,')
    warn('the current development version may be installed')
    warn('from https://github.com/rthalley/dnspython')
    warn('')
    sys.exit('Unable to continue')
elif args.debugging:
    warn()
    warn('Found dnspython version', dnspython_version, '[OK]')

# Check arguments
assert not (args.ipv4_only and args.ipv6_only) # avoid mutual exclusion
application = dict(zip( ('head', 'tail'),      # parse application path
                        os.path.split(args.application)))

assert application['tail'] in Supported_Applications

if args.application.startswith(os.getcwd()):
    application['rel'] = os.path.relpath(args.application)
else:
    application['rel'] = None

# Strip passthrough items
passthrough = list(map(lambda p: p.strip(' '), args.passthrough))

# Set up custom resolver configuration from CLI or environment
if args.resolver:
    # CLI option -r, --resolver has priority
    if args.debugging:
        warn()
        warn('  resolver:', args.resolver)
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = (
        ','.join(args.resolver).split(','))
    if args.debugging:
        warn('  nameservers:', dns.resolver.default_resolver.nameservers)
elif (('SVCBWRAP_RESOLVER' in os.environ)
      and (os.environ['SVCBWRAP_RESOLVER'])):
    # Environment variable SVCBWRAP_RESOLVER is plan B
    if args.debugging:
        warn('  SVCBWRAP_RESOLVER:', os.environ['SVCBWRAP_RESOLVER'])
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = (
        os.environ['SVCBWRAP_RESOLVER'].split(','))
    if args.debugging:
        warn('  nameservers:', dns.resolver.default_resolver.nameservers)
else:
    pass                        # Plan C: just use system default

if args.debugging:
    warn()                      # Improve layout of debugging messages 

# Perform SVCB-class DNS resolution
resolved = svcbresolve(origin_from_url(args.url))

if args.debugging:
    warn()
    pp.pprint(('resolved:', resolved))
    warn()

# Construct argument list for application
exec_path = args.application
if application['rel']:
    exec_args = [ application['rel'] ]
else:
    exec_args = [ args.application ]

# Rewrite URL if necessary
effective_url = args.url.geturl()
if (args.url.scheme == 'http' and resolved['scheme'] == 'https'):
    # SVCB/HTTPS specification requires upgrading 'http' to 'https'
    effective_url = effective_url.replace(args.url.scheme,
                                          resolved['scheme'], 1)

# Prepare for invoking application 'curl'
if application['tail'] == 'curl':
    addrkey = ':'.join((resolved['name'], str(resolved['port'])))
    addrlist = [ ]
    if args.debugging:
        warn('addrkey:', addrkey, '\n')
        
    for item in passthrough:
        # TODO: consider masking options managed by wrapper
        exec_args += item.split(' ', 1)

    if 'ipv6_addr' in resolved and not args.ipv4_only:
        addrlist.extend(resolved['ipv6_addr'])

    if 'ipv4_addr' in resolved and not args.ipv6_only:
        addrlist.extend(resolved['ipv4_addr'])

    if addrlist:
        exec_args += [ '--resolve',
                       ':'.join((addrkey, ','.join(addrlist))) ]

    if 'echconfig' in resolved:
        exec_args += [ '--echconfig', resolved['echconfig'] ]

    exec_args += [ effective_url ]

# Add code above here for any  eventual alternative supported application
if args.debugging:
    # Show (on stderr) what will be run
    warn('exec_path:', exec_path)
    warn(application['tail'], 'command:')
    for item in exec_args:
        warn('  ', item)
    warn()

if args.dry:
    # Show (on stdout) what would have been run
    print('  ', ' '.join(exec_args))

else:
    # Flush any buffered writes to stdout, stderr
    sys.stdout.flush()
    sys.stderr.flush()

    # Finally, exec application with constructed argument list
    os.execv(exec_path, exec_args)
