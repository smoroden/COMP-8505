#!/usr/bin/env ruby
require 'rubygems'
require 'pcaprub'
require 'pp'

# Opens up the nic for capture.
capture = PCAPRUB::Pcap.open_live('em1', 65535, true, 0)
capture.setfilter('tcp[2:2] = 56566')
while 1==1

  pkt = capture.next()
  if pkt
    puts "captured packet"
  end

end