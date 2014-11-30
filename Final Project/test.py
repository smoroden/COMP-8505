import netifaces as ni


ip = ni.ifaddresses('em1')[2][0]['addr']
print ip

interface_list = ni.interfaces()


print