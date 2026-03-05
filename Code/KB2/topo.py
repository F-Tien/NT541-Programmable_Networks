from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import OVSSwitch

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        #Add router
        router = self.addHost('r')
        
        # Add hosts
        Host01 = self.addHost( 'sales1', ip='10.0.1.1/24', defaultRoute='via 10.0.1.254')
        Host02 = self.addHost( 'sales2', ip='10.0.1.2/24', defaultRoute='via 10.0.1.254' )
        Host03 = self.addHost( 'sales3', ip='10.0.1.3/24', defaultRoute='via 10.0.1.254' )
        Host04 = self.addHost( 'sales4', ip='10.0.1.4/24', defaultRoute='via 10.0.1.254' )

        Host05 = self.addHost( 'it1', ip='10.0.2.1/24', defaultRoute='via 10.0.2.254' )
        Host06 = self.addHost( 'it2', ip='10.0.2.2/24', defaultRoute='via 10.0.2.254' )
        Host07 = self.addHost( 'it3', ip='10.0.2.3/24', defaultRoute='via 10.0.2.254' )
        Host08 = self.addHost( 'it4', ip='10.0.2.4/24', defaultRoute='via 10.0.2.254' )

        Host09 = self.addHost( 'visitor1', ip='10.0.4.1/24', defaultRoute='via 10.0.4.254' )
        Host10 = self.addHost( 'visitor2', ip='10.0.4.2/24', defaultRoute='via 10.0.4.254' )
        Host11 = self.addHost( 'visitor3', ip='10.0.4.3/24', defaultRoute='via 10.0.4.254' )
        Host12 = self.addHost( 'visitor4', ip='10.0.4.4/24', defaultRoute='via 10.0.4.254' )

        app = self.addHost('app', ip='10.0.3.10/24', defaultRoute='via 10.0.3.254')


             # Add switches
        Switch1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        Switch2 = self.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
        Switch3 = self.addSwitch('s3', cls=OVSSwitch, protocols='OpenFlow13')
        Switch4 = self.addSwitch('s4', cls=OVSSwitch, protocols='OpenFlow13')

        # Add links
        # SW1 - Hosts
        self.addLink( Host01, Switch1 )
        self.addLink( Host02, Switch1 )
        self.addLink( Host03, Switch1 )
        self.addLink( Host04, Switch1 )

        # SW2 - Hosts
        self.addLink( Host05, Switch2 )
        self.addLink( Host06, Switch2 )
        self.addLink( Host07, Switch2 )
        self.addLink( Host08, Switch2 )

        self.addLink(app, Switch3)

        # SW3 - Hosts
        self.addLink( Host09, Switch4 )
        self.addLink( Host10, Switch4 )
        self.addLink( Host11, Switch4 )
        self.addLink( Host12, Switch4 )

        # Switch-to-Switch
        self.addLink(router, Switch1)  # r-eth0 -> 10.0.1.0/24
        self.addLink(router, Switch2)  # r-eth1 -> 10.0.2.0/24
        self.addLink(router, Switch3)  # r-eth2 -> 10.0.3.0/24
        self.addLink(router, Switch4)  # r-eth3 -> 10.0.4.0/24

def setup_network():
    net = Mininet(
        topo=MyTopo(),
        controller=None,
        autoSetMacs=True
    )

    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    net.start()

    # Configure Router
    r = net.get('r')
    r.cmd("ifconfig r-eth0 10.0.1.254/24")
    r.cmd("ifconfig r-eth1 10.0.2.254/24")
    r.cmd("ifconfig r-eth2 10.0.3.254/24")
    r.cmd("ifconfig r-eth3 10.0.4.254/24")
    r.cmd("sysctl -w net.ipv4.ip_forward=1")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    setup_network()

# For mn --custom
topos = { 'mytopo': (lambda: MyTopo()) }