#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'
require 'macaddr'
require 'pp'

include PacketFu

iface = 'em1'

# Opens up the nic for capture.
def sniff(iface)
  pp 'Sniffing...'
  cap = Capture.new(:iface => iface, :start => true, :filter => 'udp and port 53', :save => true)
  cap.stream.each do |p|
    packet = Packet.parse p

    $dnsQuery = packet.payload[2].unpack('h*')[0].chr+packet.payload[3].unpack('h*')[0].chr

    if $dnsQuery == '10'
      domain, trans_id = get_info(packet)
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
      domain += packet.payload[i]
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
  pp packet.payload
  transaction_id = '0x'+packet.payload[0].unpack('H*')[0]+packet.payload[1].unpack('H*')[0]
  puts transaction_id
  return domain, transaction_id.hex
end

sniff(iface)