# Node in 3DCoP network, one vantage point in a scenario
class Node:
    def __init__(self, own_network, name, has_amplifiers, has_bots, victim_ip):
        self.own_network = own_network
        self.name = name
        self.has_amplifiers = has_amplifiers
        self.has_bots = has_bots
        self.victim_ip = victim_ip


######################################################################
###            Edit this section to define node topology           ###
######################################################################

# Make sure each node has a unique name and class B / 16-bit network prefix
# such as '172.16'. Multiple attack vectors may be present simultaneously:
#
#  amplifiers: if a network has_amplifiers, it amplifies and reflects traffic
#  bots: if a network has_bots, it emits floods as a botnet would
#  probes: scan and probe all nodes with TCP connection attempts
#
# Scanners, if enabled, constantly scan/attack all defined networks.
# For amplifiers and bots, only one node (and one IP) can be the victim.
#
# Node('ip.prefix', 'Name', has_amplifiers, has_bots, victim_ip)
nodeA = Node('172.16',  'A',    True,   True,   None)
nodeB = Node('172.17',  'B',    True,   False,  None)
nodeC = Node('172.18',  'C',    False,  True,   None)
nodeD = Node('172.19',  'D',    False,  True,   None)
nodeE = Node('172.20',  'E',    True,   False,  None)
nodeF = Node('172.21',  'F',    False,  False,  '172.21.99.99')

# List all nodes
nodelist = [nodeA, nodeB, nodeC, nodeD, nodeE, nodeF]

# Each node/network space contains multiple amplifiers or bots (flooders)
amplifiers_per_node = 5
bots_per_node = 10

# The traffic records in the noise dataset form the basis for all output.
# Define the interval for inserting synthetic flow records among the noise,
# where the minimum is 0 and means the highest volume of synthetic traffic.
synthetic_interval = 5

# Scanning bots probe all networks with TCP connection attempts.
# These are random sources that are scanning random destinations, with no response.
# probes_enabled is 1 or 0
# probes_duration is the number of seconds the attempt lasts
# probes_per_timestep is the number of random probes per time
probes_enabled = 1
probes_duration = 5
probes_per_timestep = 5
probes_dst_port = 2323

# Modeling characteristics of UDP reflection-amplification flows
reflect_service_port = 123
reflect_client_port = 80
reflect_input_packets_per_flow = 1
reflect_input_bytes_per_flow = 200
reflect_output_packets_per_flow = 300
reflect_output_bytes_per_flow = 200000

# Modeling characteristics of bots or compromised systems that emit UDP floods.
# These are no input flows for these, so we only see their outputs.
bot_dst_port = 53
bot_output_packets_per_flow = 20
bot_output_bytes_per_flow = 6000

# Duration in seconds. For UDP floods this relates to the router NetFlow config.
flow_duration = 55

######################################################################
