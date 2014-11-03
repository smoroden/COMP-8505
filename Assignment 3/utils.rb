################ User Defined ##################
$iface='em1'
$router_ip='192.168.0.100'
CONFIG_FILE = 'config.txt'
################################################

$target_ip = nil

#this prints usage example for the program
def usage()
  puts("\nUsage: dns_spoof.rb v <victim's IP> -r [router IP] -i [interface]")
  puts("\n\e[1m-v,--victim;\e[0m \e[3mvictim's IP address\e[0m")
  puts("  This will be the IP address of the person you wish to perform a DNS")
  puts("  spoofing attack on.")
  puts("\e[1m-r,--router;\e[0m \e[3mrouter IP address\e[0m")
  puts("  This will be the IP of the router on the network you wish to perform")
  puts("  your attack on.\n")
  puts("\e[1m-i,--interface;\e[0m \e[3mnetwork interface\e[0m")
  puts("  This will be the network interface card ID you wish to perform your")
  puts("  attack on.\n")
  exit
end

def config_error()
  puts("\n\e[1;31;40mERROR - A problem occurred while attempting to run dnsspoof.rb. Please")
  puts("ensure your config file is setup correctly.\n\e[0;0;0")
  exit
end