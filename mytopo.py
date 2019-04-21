from mininet.topo import Topo
class MyTopo( Topo ):
    def build(self):
        # Add hosts
        hosth1 = self.addHost('h1')
        hosth2 = self.addHost('h2')
        hosth3 = self.addHost('h3')
        hosth4 = self.addHost('h4')
        hosth5 = self.addHost('h5')
        hosth6 = self.addHost('h6')

        # Add Switches
        switchs1 = self.addSwitch('s1', listenPort=6634)
        switchs2 = self.addSwitch('s2', listenPort=6634)
        switchs3 = self.addSwitch('s3', listenPort=6634)
        switchs4 = self.addSwitch('s4', listenPort=6634)
        switchs5 = self.addSwitch('s5', listenPort=6634)

        # Add Links
        self.addLink(hosth1, switchs3)
        self.addLink(hosth2, switchs3)
        self.addLink(hosth2, switchs4)
        self.addLink(hosth3, switchs4)
        self.addLink(hosth4, switchs4)
        self.addLink(hosth5, switchs4)
        self.addLink(hosth5, switchs5)
        self.addLink(hosth6, switchs5)
        self.addLink(switchs3, switchs1)
        self.addLink(switchs4, switchs1)
        self.addLink(switchs4, switchs2)
        self.addLink(switchs5, switchs2)

topos = { 'mytopo': (lambda: MyTopo()) }
