#!/usr/bin/env ruby
require 'rubygems'
require 'packetfu'
require 'pp'

include PacketFu

iface = ARGV[0] || "em1"
# Opens up the nic for capture.
def sniff(iface)
  cap = Capture.new(:iface => iface, :start => true)
  cap.stream.each do |p|
    pkt = Packet.parse p
    if pkt.is_ip?
      next if pkt.ip_saddr == Utils.ifconfig(iface)[:ip_saddr]
      packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
      puts "%-15s -> %-15s %-4d %s" % packet_info
      pp pkt
    end
  end
end


sniff(iface)