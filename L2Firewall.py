from pox.core import core
from pox.lib.revent import *
from pox.lib.addresses import EthAddr
import pox.openflow.libopenflow_01 as of

#The firewall rules declared statically
rules = [
['00:00:00:00:00:01','00:00:00:00:00:02'],
['00:00:00:00:00:02','00:00:00:00:00:04'],
['00:00:00:00:00:08','00:00:00:00:00:03'],
['00:00:00:00:00:07','00:00:00:00:00:02']
]

#Create a class for our firewall
class L2Firewall(EventMixin):
    # Register to the openflow controller
	def __init__(self):
		self.listenTo(core.openflow)

    # When the connection comes, register our rules to the switch
	def _handle_ConnectionUp(self, event):
		for r in rules:
            # Setup the matcher
			rule = of.ofp_match()
			rule.dl_src = EthAddr(r[0])
			rule.dl_dst = EthAddr(r[1])

            # Set the rule to the flow modifier
			flow_modifier = of.ofp_flow_mod()
			flow_modifier.match = rule

            # Send it to the switch
			event.connection.send(flow_modifier)

# Register our class with pox
def launch():
	core.registerNew(L2Firewall)