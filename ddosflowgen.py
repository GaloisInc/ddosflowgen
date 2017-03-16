#
# ddosflowgen models a DDoS attack and generates traffic datasets from N views
#
# ddosflowgen takes a traffic noise dataset, along with a topology definition,
# to generate synthetic attack traffic. The resulting flow records containing
# a mix of noise plus attack traffic are written for every 3DCoP node/network.
#
# Attack types as defined in the topology, can be:
#  * amplifiers - UDP reflectors/amplifiers such as DNS and NTP
#  * bots that flood - send UDP floods such as DNS queries, like Mirai attacking
#  * probes - bots trying TCP connections to random dests, like Mirai scanning
#
# Needs python3
#
# Example:
#
# python3 ddosflowgen.py --dataset dataset --outdir result
#
# The noise dataset files "inbound" and "outbound" should be obtained from SiLK dumps using:
# rwfilter --sensor=S0 --type=in,inweb,inicmp --start-date=time --end-date=time --protocol=0- --pass=stdout | rwcut
# rwfilter --sensor=S0 --type=out,outweb,outicmp --start-date=time --end-date=time --protocol=0- --pass=stdout | rwcut

from topologies import mixed_big as topology
import argparse
import datetime
import hashlib
import os
import random
import sys

def die(fmt, *args, **kwargs):
    '''Display an error message on stderr and then exit.'''
    sys.stderr.write(fmt.format(*args, **kwargs) + '\n')
    sys.exit(1)

def md5it(text):
    digest = hashlib.md5(text.encode('utf-8')).digest()
    return digest

# Class A (first octet of IP) that are reserved and not usable
RESERVED_CLASS_A = (0, 10, 127, 172, 255)

# SiLK rwcut fields
FIELD_SRCIP     = 0
FIELD_DSTIP     = 1
FIELD_SRCPORT   = 2
FIELD_DSTPORT   = 3
FIELD_PROTO     = 4
FIELD_PACKETS   = 5
FIELD_BYTES     = 6
FIELD_FLAGS     = 7
FIELD_STIME     = 8
FIELD_DURATION  = 9
FIELD_ETIME     = 10
FIELD_SENSOR    = 11
FIELD_TIMEDATE  = 12    # not an actual field, just using this for storage

class FlowGen:

    # Construct the object
    def __init__(self, args):
        self.args = args
        # Check arguments
        if not args.datasetdir:
            die('Must use --dataset to specify the path of noise dataset. '
                        'Must contain files: inbound, outbound')
        if not args.outdir:
            die('Must use --outdir to specify the path that will store the '
                        'generated outputs, numbered by 3DCoP node number')
        for node in topology.nodelist:
            if node.victim_ip != None:
                self.victim_node = node     # Figure out the victim node
                if (node.has_amplifiers == True) or (node.has_bots == True):
                    die('Error in topology: victim should not contain attackers')
        self.create_outfiles()

    def run(self):
        print("Processing inbound...")
        with open(os.path.join(self.args.datasetdir, 'inbound'), 'r') as inbound:
            self.bot_portcount = 0
            self.foreach_noise(inbound, True)
        print("Processing outbound...")
        with open(os.path.join(self.args.datasetdir, 'outbound'), 'r') as outbound:
            self.bot_portcount = 0
            self.foreach_noise(outbound, False)
        self.close()

    def foreach_noise(self, noisefile, is_inbound):
        counter = 0
        for line in noisefile:
            if counter > topology.synthetic_interval:
                add_attack = True
                counter = 1
            else:
                add_attack = False
                counter += 1
            parsed = self.parse_line(line)
            for node in topology.nodelist:
                self.rewrite(parsed, is_inbound, node, add_attack)
        # Flush all files when we're done with a direction
        self.flush_all()

    # Parse a line from the non-attack dataset. We also parse the start time
    # to facilitate inserting new synthetic flows with consistent timestamps.
    # Returns list of parsed fields, as well as additional timestamp field.
    def parse_line(self, line):
        parsed = line.split('|')
        for field in range(0, len(parsed)):
            if field == 7:  # leave whitespace alone for TCP flags (bitmap)
                continue
            parsed[field] = parsed[field].strip()
        if parsed[FIELD_STIME] != 'sTime':
            # Parse time stamp too and store it for convenience
            parsed[FIELD_TIMEDATE] = datetime.datetime.strptime(parsed[FIELD_STIME], '%Y/%m/%dT%H:%M:%S.%f')
        return parsed


    # Output one line with rewritten IPs, and insert synthetic attack traffic too.
    # Internal-side addreses get reallocated under the node's own network space,
    # while external-side addresses get remapped deterministically for consistency.
    # Different nodes see different external addresses.
    def rewrite(self, parsed, is_inbound, node, add_attack):
        if is_inbound == True:
            externalfield = FIELD_SRCIP
            internalfield = FIELD_DSTIP
            outfile = node.result_inbound
        else:
            internalfield = FIELD_SRCIP
            externalfield = FIELD_DSTIP
            outfile = node.result_outbound
        if parsed[FIELD_SRCIP] != 'sIP':
            # this is not a header line; let's transform it
            # transform internal IP
            digest = md5it(parsed[internalfield])
            parsed[internalfield] = "{0}.{1}.{2}".format(node.own_network, digest[0], digest[1])
            # transform external IP to hash(old_ip + 3dcop_identifier)
            digest = md5it(str(parsed[externalfield] + node.name))
            pos = 0
            # in case of reserved address, use a different part of the digest
            while digest[pos] in RESERVED_CLASS_A:
                pos += 1    # vanishingly small risk of overflow
            parsed[externalfield] = "{0}.{1}.{2}.{3}".format(digest[pos], digest[pos+1], digest[pos+2], digest[pos+3])
        self.print_rwcut_line(parsed, outfile)
        if add_attack:
            sTime = parsed[FIELD_TIMEDATE]
            if node.has_amplifiers == True:
                self.gen_amplifiers(parsed, sTime, is_inbound, node, outfile)
            if node.has_bots == True:
                self.gen_bots(parsed, sTime, is_inbound, node, outfile)
            if node == self.victim_node:
                self.gen_victim(parsed, sTime, is_inbound)
            if topology.probes_enabled == True:
                self.gen_probes(parsed, sTime, is_inbound, node, outfile)


    # Generate attack traffic at amplifiers. Note that each 3DCoP network space
    # contains "topology.amplifiers_per_node" many amplifier IPs
    def gen_amplifiers(self, parsed, start_time, is_inbound, node, outfile):
        # we will construct synthetic flows
        synth = list(parsed)    # use our own copy
        # There may be several amplifiers/reflectors within this network
        for ampid in range(0, topology.amplifiers_per_node):
            # Create this amplifier's address. Note this is consistent inbound and outbound.
            digest = md5it(node.own_network + str(ampid))
            amp_ip = "{0}.{1}.{2}".format(node.own_network, digest[0], digest[1])
            offset = datetime.timedelta(0, 0, 0, 10*(1+ampid))
            duration = datetime.timedelta(0, topology.flow_duration)
            flowstart = start_time + offset
            flowend = start_time + offset + duration
            synth[FIELD_STIME] = flowstart.strftime('%Y/%m/%dT%H:%M:%S.%f')[:-3]
            synth[FIELD_DURATION] = '{0:.3f}'.format(topology.flow_duration)
            synth[FIELD_ETIME] = flowend.strftime('%Y/%m/%dT%H:%M:%S.%f')[:-3]
            synth[FIELD_PROTO] = '17'        # UDP
            synth[FIELD_FLAGS] = '        '  # TCP flags not relevant
            if is_inbound == True:
                # Into amplifier
                synth[FIELD_SRCIP] = self.victim_node.victim_ip
                synth[FIELD_DSTIP] = amp_ip
                synth[FIELD_SRCPORT] = str(topology.reflect_client_port)
                synth[FIELD_DSTPORT] = str(topology.reflect_service_port)
                synth[FIELD_PACKETS] = str(topology.reflect_input_packets_per_flow \
                                    + random.randint(0, topology.reflect_input_packets_per_flow))
                synth[FIELD_BYTES] = str(topology.reflect_input_bytes_per_flow \
                                    + random.randint(0, topology.reflect_input_bytes_per_flow))
            else:
                # Out of amplifier
                synth[FIELD_DSTIP] = self.victim_node.victim_ip
                synth[FIELD_SRCIP] = amp_ip
                synth[FIELD_DSTPORT] = str(topology.reflect_client_port)
                synth[FIELD_SRCPORT] = str(topology.reflect_service_port)
                synth[FIELD_PACKETS] = str(topology.reflect_output_packets_per_flow \
                                    + random.randint(0, topology.reflect_output_packets_per_flow))
                synth[FIELD_BYTES] = str(topology.reflect_output_bytes_per_flow \
                                    + random.randint(0, topology.reflect_output_bytes_per_flow))
            # Print one flow for each amplifier
            self.print_rwcut_line(synth, outfile)


    # Generate bot attack traffic, which we simplify into just dumb floods.
    # These may be things like hammering DNS (udp/53) queries at the victim.
    def gen_bots(self, parsed, start_time, is_inbound, node, outfile):
        # we will construct synthetic flows
        if is_inbound == True:
                return          # we don't model this (e.g. command-and-control)
        synth = list(parsed)    # use our own copy
        # There may be several bots within this network
        for botid in range(0, topology.bots_per_node):
            # Create this bot's address. Note this is consistent inbound and outbound.
            digest = md5it(node.own_network + str(botid) + 'bot')
            bot_ip = "{0}.{1}.{2}".format(node.own_network, digest[0], digest[1])
            offset = datetime.timedelta(0, 0, 0, 10*(1+botid))
            duration = datetime.timedelta(0, topology.flow_duration)
            flowstart = start_time + offset
            flowend = start_time + offset + duration
            synth[FIELD_STIME] = flowstart.strftime('%Y/%m/%dT%H:%M:%S.%f')[:-3]
            synth[FIELD_DURATION] = '{0:.3f}'.format(topology.flow_duration)
            synth[FIELD_ETIME] = flowend.strftime('%Y/%m/%dT%H:%M:%S.%f')[:-3]
            synth[FIELD_PROTO] = '17'        # UDP
            synth[FIELD_FLAGS] = '        '  # TCP flags not relevant
            if is_inbound == False:
                # We only generate the outbound traffic from a node
                synth[FIELD_SRCIP] = bot_ip
                synth[FIELD_DSTIP] = self.victim_node.victim_ip
                synth[FIELD_SRCPORT] = self.get_bot_src_port(digest)
                synth[FIELD_DSTPORT] = str(topology.bot_dst_port)
                synth[FIELD_PACKETS] = str(topology.bot_output_packets_per_flow \
                                    + random.randint(0, topology.bot_output_packets_per_flow))
                synth[FIELD_BYTES] = str(topology.bot_output_bytes_per_flow \
                                    + random.randint(0, topology.bot_output_bytes_per_flow))
            # Print one flow for each amplifier
            self.print_rwcut_line(synth, outfile)


    # Generate attack traffic seen at the victim.
    # Perhaps it would be more efficient to buffer the output as we write each earlier amplifier?
    def gen_victim(self, parsed, start_time, is_inbound):
        # we will construct synthetic flows, only for the inbound direction
        synth = list(parsed)
        if is_inbound == True:
            # Inbound attack traffic is the aggregation of all amplifiers
            for ampnode in topology.nodelist:
                if ampnode.has_amplifiers == True:
                    # There may be several amplifiers/reflectors within this network
                    for ampid in range(0, topology.amplifiers_per_node):
                        digest = md5it(ampnode.own_network + str(ampid))
                        amp_ip = "{0}.{1}.{2}".format(ampnode.own_network, digest[0], digest[1])
                        offset = datetime.timedelta(0, 0, 0, 10*(1+ampid))
                        duration = datetime.timedelta(0, topology.flow_duration)
                        flowstart = start_time + offset
                        flowend = start_time + offset + duration
                        synth[FIELD_STIME] = flowstart.strftime('%Y/%m/%dT%H:%M:%S.%f')[:-3]
                        synth[FIELD_DURATION] = '{0:.3f}'.format(topology.flow_duration)
                        synth[FIELD_ETIME] = flowend.strftime('%Y/%m/%dT%H:%M:%S.%f')[:-3]
                        synth[FIELD_PROTO] = '17'        # UDP
                        synth[FIELD_FLAGS] = '        '  # TCP flags not relevant
                        synth[FIELD_DSTIP] = self.victim_node.victim_ip
                        synth[FIELD_SRCIP] = amp_ip
                        synth[FIELD_DSTPORT] = str(topology.reflect_client_port)
                        synth[FIELD_SRCPORT] = str(topology.reflect_service_port)
                        synth[FIELD_PACKETS] = str(topology.reflect_output_packets_per_flow \
                                            + random.randint(0, topology.reflect_output_packets_per_flow))
                        synth[FIELD_BYTES] = str(topology.reflect_output_bytes_per_flow \
                                            + random.randint(0, topology.reflect_output_bytes_per_flow))
                        self.print_rwcut_line(synth, self.victim_node.result_inbound)
            # And aggregation of all bots
            for botnode in topology.nodelist:
                if botnode.has_bots == True:
                    # There may be several bots within this network
                    for botid in range(0, topology.bots_per_node):
                        digest = md5it(botnode.own_network + str(botid) + 'bot')
                        bot_ip = "{0}.{1}.{2}".format(botnode.own_network, digest[0], digest[1])
                        offset = datetime.timedelta(0, 0, 0, 10*(1+botid))
                        duration = datetime.timedelta(0, topology.flow_duration)
                        flowstart = start_time + offset
                        flowend = start_time + offset + duration
                        synth[FIELD_STIME] = flowstart.strftime('%Y/%m/%dT%H:%M:%S.%f')[:-3]
                        synth[FIELD_DURATION] = '{0:.3f}'.format(topology.flow_duration)
                        synth[FIELD_ETIME] = flowend.strftime('%Y/%m/%dT%H:%M:%S.%f')[:-3]
                        synth[FIELD_PROTO] = '17'        # UDP
                        synth[FIELD_FLAGS] = '        '  # TCP flags not relevant
                        synth[FIELD_SRCIP] = bot_ip
                        synth[FIELD_DSTIP] = self.victim_node.victim_ip
                        synth[FIELD_SRCPORT] = self.get_bot_src_port(digest)
                        synth[FIELD_DSTPORT] = str(topology.bot_dst_port)
                        synth[FIELD_PACKETS] = str(topology.bot_output_packets_per_flow \
                                            + random.randint(0, topology.bot_output_packets_per_flow))
                        synth[FIELD_BYTES] = str(topology.bot_output_bytes_per_flow \
                                            + random.randint(0, topology.bot_output_bytes_per_flow))
                        self.print_rwcut_line(synth, self.victim_node.result_inbound)


    # We want the flooding bots to use a non-constant source port.
    # Generate it deterministically from the bot digest plus port counter.
    # Because gen_bots and gen_victim iterate over the same list, this should
    # create consistent port numbers both in the emitting network and victim view.
    # TODO: this isn't quite right because in/out references are different
    def get_bot_src_port(self, digest):
        current = self.bot_portcount + digest[2] + digest[3] + digest[4] \
            + digest[5] + digest[6] + digest[7] + digest[8] + digest[9] + digest[10]
        src_port = 10000 + (current % 55536)
        self.bot_portcount += 1
        return str(src_port)

    # Generate probes from a botnet that is scanning to try and infect other
    # hosts, like Mirai scanning for open telnet ports. Analysts have reported
    # to us that they notice these when there are large number of these flows
    # and a large number of unique destination IPs; we generate these randomly
    def gen_probes(self, parsed, start_time, is_inbound, node, outfile):
        # we will construct synthetic flows, only for the inbound direction
        synth = list(parsed)
        if is_inbound == True:
            for probe in range(0, topology.probes_per_timestep):
                offset = datetime.timedelta(0, 0, 0, 15*(1+probe))
                duration = datetime.timedelta(0, topology.probes_duration)
                flowstart = start_time + offset
                flowend = start_time + offset + duration
                synth[FIELD_STIME] = flowstart.strftime('%Y/%m/%dT%H:%M:%S.%f')[:-3]
                synth[FIELD_DURATION] = '{0:.3f}'.format(topology.probes_duration)
                synth[FIELD_ETIME] = flowend.strftime('%Y/%m/%dT%H:%M:%S.%f')[:-3]
                synth[FIELD_PROTO] = '6'        # TCP
                synth[FIELD_FLAGS] = ' S      ' # only SYNs
                synth[FIELD_SRCIP] = self.gen_rand_ip(None)
                synth[FIELD_DSTIP] = self.gen_rand_ip(node.own_network)
                synth[FIELD_SRCPORT] = str(random.randint(49152, 65535)) # ephemeral port
                synth[FIELD_DSTPORT] = str(topology.probes_dst_port)
                synth[FIELD_PACKETS] = str(1 + topology.probes_duration)
                synth[FIELD_BYTES] = str(64 * (1 + topology.probes_duration))
                self.print_rwcut_line(synth, outfile)

    # Generate a random IP address.
    # If a class B prefix is provided, only two bytes are generated.
    # If prefix is None, then all four bytes are generated.
    def gen_rand_ip(self, prefix):
        if prefix == None:
            getrand = True
            while getrand:
                octet1 = random.randint(1, 255)
                getrand = (octet1 in RESERVED_CLASS_A)
            octet2 = random.randint(1, 255)
            prefix = "{0}.{1}".format(octet1, octet2)
        octet3 = random.randint(1, 255)
        octet4 = random.randint(1, 255)
        return "{0}.{1}.{2}".format(prefix, octet3, octet4)

    def print_rwcut_line(self, fields, outfile):
        print(fields[FIELD_SRCIP].rjust(39), end='|', file=outfile, flush=False)
        print(fields[FIELD_DSTIP].rjust(39), end='|', file=outfile, flush=False)
        print(fields[FIELD_SRCPORT].rjust(5), end='|', file=outfile, flush=False)
        print(fields[FIELD_DSTPORT].rjust(5), end='|', file=outfile, flush=False)
        print(fields[FIELD_PROTO].rjust(3), end='|', file=outfile, flush=False)
        print(fields[FIELD_PACKETS].rjust(10), end='|', file=outfile, flush=False)
        print(fields[FIELD_BYTES].rjust(10), end='|', file=outfile, flush=False)
        print(fields[FIELD_FLAGS], end='|', file=outfile, flush=False)  # TCP flags left alone
        print(fields[FIELD_STIME].rjust(23), end='|', file=outfile, flush=False)
        print(fields[FIELD_DURATION].rjust(9), end='|', file=outfile, flush=False)
        print(fields[FIELD_ETIME].rjust(23), end='|', file=outfile, flush=False)
        print(fields[FIELD_SENSOR].rjust(3), end='|\n', file=outfile, flush=False)


    def create_outfiles(self):
        if os.path.exists(self.args.outdir):
            die('The --outdir path already exists. Aborting, not clobbering existing results.')
        os.makedirs(self.args.outdir)
        for node in topology.nodelist:
            in_fname = node.name + '-inbound.tuc'
            out_fname = node.name + '-outbound.tuc'
            node.result_inbound =  open(os.path.join(self.args.outdir, in_fname), 'w')
            node.result_outbound = open(os.path.join(self.args.outdir, out_fname), 'w')


    def close(self):
        for node in topology.nodelist:
            node.result_inbound.close()
            node.result_outbound.close()
            print('Closed result files for ' + node.name)


    def flush_all(self):
        for node in topology.nodelist:
            node.result_inbound.flush()
            node.result_outbound.flush()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DDoS Flow Generator and Address Rewriter')
    parser.add_argument('--dataset', action='store', dest='datasetdir')
    parser.add_argument('--outdir', action='store', dest='outdir')
    generator = FlowGen(parser.parse_args())
    generator.run()
