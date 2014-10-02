#!/usr/bin/env ruby
require 'rubygems'
require 'packetfu'
require 'pp'
                    #important website http://www.rubydoc.info/github/todb/packetfu/frames/PacketFu/Inject
include PacketFu
$password = "zdehjk"


  def xor(payload)
    output = ''
    i = 0
    payload.each_char { |c|
      pass_char = $password[i]
      xor = c.ord ^ pass_char.ord
      output << xor
      i+=1
      if i == ($password.size - 1)
        i = 0
      end
    }
    return output
  end


iface = ARGV[0] || "em1"

# Opens up the nic for capture.
def sniff(iface)
  cap = Capture.new(:iface => iface, :start => true, :filter => 'port 22')
  cap.stream.each do |p|
    packet = Packet.parse p
    #pp packet
    cmd = xor packet.payload
    pp cmd
    pp packet.payload
    #value = `cmd`

    pp packet.ip_dst_readable
  end


end

#cap = PacketFu::Capture.new(:start => true, :iface => iface, :promisc => true)
#cap.show_live(:filter => 'port 22')

sniff(iface)

