#!/usr/bin/python3

# Version: 1.5
# Script Name : PTX10_drop_tshoot.py
# Description : 
    # OFF-Box PyEz script to troubleshoot paradise data errors and normal discards.
    # Provide username with (-u) flag or allow the script to detect the username.
    # Or feel free to hardcode the username and password.
# Requirements :
	# Scripts needs ssh/netconf so it needs username and password.
	# Remote user needs privileges to run commands on Juniper box.
	# Script does NOT change configuration.

# Generic python imports 
import logging
import argparse
import inspect
import re
import signal
import sys

# Scapy imports
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import getpass
from time import sleep

# Juniper imports
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError
from lxml import etree

# !!!!!!!!!!!!!!!!!!!!!! DO NOT CHANGE THIS SECTION !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# Add/Remove trapcodes only if tests have been performed.
allowed_trap_codes = [160, 163, 252]

# Validated platform / version 
validated_platforms = 	{	'ptx10008': [['17.2R1-S'],['LC1101 - 30C / 30Q / 96X']],
							'ptx1000': [['17.2R1-S'],['PTX1000']],
							'ptx5000': [['17.2R1-S'], ['FPC-P2']]
						}
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


# Get cli arguments.
parser = argparse.ArgumentParser()
parser.add_argument('-j', required=True, help = 'Host.')
parser.add_argument('-l', required=False, help = 'Line card/FPC#.')
parser.add_argument('-d', required=False, action='store_true', help = 'Debug flag.')
parser.add_argument('-u', required=False, help = 'Username (if other than the one running the script.')

args = parser.parse_args()

# Define object.
class main(object):
	def __init__(self,args):
		self.dst_host = args.j
		self.fpc = [""]
		self.debug = args.d
		
		if args.u is None:
			self.username = getpass.getuser()
		else:
			self.username = args.u
		try:
			a=1
			#self.password = getpass.getpass(str(self.username)+" password: ")
		except KeyboardInterrupt as err:
			print (str(err)+"Interrupted by user.")
			sys.exit()
		self.username = 'username'
		self.password = 'Password'
		self.__main__()

	# Main wrapping function. For debugging, follow this function.
	def __main__(self):
		''' Trap Ctrl+C and do a clean exit. '''
		signal.signal(signal.SIGINT, self.signal_handler_quit)

		''' Print info. '''
		print ('\033[0;30;42mTroubleshooting NORMAL DISCARDS (BAD ROUTE DISCARDS) & DATA ERRORS on host '+args.j+'. DO NOT INTERRUPT THIS SCRIPT!!!\033[0m')

		''' Open device connection '''
		dev = self.dev_connection()

		''' Check if it's a platform/version alidated in CSIM. '''
		this_platform = self.check_valid_platform(dev)
		if this_platform is not True:
			print ('This script will not work on this system: '+self.hwModel+'. Exiting')
			sys.exit()

		''' slots = Online FPCs.'''
		slots = self.rpc_get_online_fpc(dev)
		if slots is False:
			print ('Could not get list of online FPCs. Exiting.')
			sys.exit(1)
		else:
			print ('\033[32mOnline FPCs slots whitelisted for this platform('+str(self.hwModel)+'): '+str(slots)+'\033[0m')

		''' From Online FPCs, check where is data error/normal discard increments. '''
		data_error_fpcs = self.check_data_error_deltas(dev, slots)
		if data_error_fpcs is False or data_error_fpcs is None:
			print ('There are no FPCs with incrementing Data Errors or Normal Discards.')
			sys.exit()

		''' Only a strict list of traps are validated (not to crash the FPC). So we'll validate this.'''
		trap_fpc_pes = self.check_fpc_trap_drops(dev, data_error_fpcs)
		if trap_fpc_pes is False:
			print('This FPC does not trap packets with tested trapcodes or all trapcodes rate=0pps. Check with Juniper for more info or run with debug (-d) or check traps manually.'+str(trap_fpc_pes))
			sys.exit()

		print ("\033[0;30;42m           FPC  PE   TRAP     TRAPNAME\033[0m")
		for i in range(0,len(trap_fpc_pes)):
			print ('\033[0;30;42mOption '+str(i)+': '+str(trap_fpc_pes[i])+'\033[0m')

		''' If Python3, use input(). For python 2, use raw_input(). Dont use input() in python2. It's dangerous because it evaluates input code.'''
		if sys.version_info[0] > 2:
			choice = input("Which FPC / PE / TRAP ? Enter option:")
		else:
			choice = raw_input("Which FPC / PE / TRAP ? Enter option:")

		''' Validate the option entered by user. No non-digits/outofrange digits are accepted. '''		
		try:
			if int(choice) in range(0, len(trap_fpc_pes)):
				print ("You selected: "+str(trap_fpc_pes[int(choice)]))
			else:
				print ('\033[31mYOU\'VE BEEN NAUGHTY. ENTER AN OPTION ONLY NEXT TIME. I WILL COMMIT SEPPUKU NOW.\033[0m')
				quit()
		except ValueError:
			print ('\033[31mYOU\'VE BEEN NAUGHTY. ENTER A DIGIT ONLY NEXT TIME. I WILL COMMIT SEPPUKU NOW.\033[0m')
			quit()
		except:
			quit()

		''' At this point, all checks are passed, so we go fetch the syslog buffer, extract IFD and PAYLOAD and convert to scapy packet.'''
		syslog_buffer = self.rpc_get_syslog_payload(dev, trap_fpc_pes[int(choice)][0], trap_fpc_pes[int(choice)][1], trap_fpc_pes[int(choice)][2])
		for element in syslog_buffer:
			if isinstance(element, list):
				print ('\033[0;30;42m************************ IFD:'+element[0]+', PARENT:'+element[1]+' ******************************\033[0m')
			else:
				#print (element)
				element_bin = self.hex_to_pkt(element)
				'''If L2 header is missing, hex starts from IPv4/IPv6 version.'''
				if re.match(r'^4', element, flags=0) and not re.match(r'^[a-f0-9]{24}(0800)|(86dd)|(0806)|(8100)', element, flags=0):
					'''V4 should alway start with 4, regardless of IPv4 header length.'''
					element = IP(element_bin)
					#print(element.getlayer(IP))
				elif re.match(r'^6', element, flags=0) and not re.match(r'^[a-f0-9]{24}(0800)|(86dd)|(0806)|(8100)', element, flags=0):
					'''IPv6 version starts with 6, regardless of TOS value'''
					element = IPv6(element_bin)
				elif re.match(r'^[a-f0-9]{24}(0800)|(86dd)|(0806)|(8100)', element, flags=0):
					'''If not v4/v6, check if byte offset 13 is IPv4 (0x0800), IPv6(0x86dd), ARP (0x0806) or VLAN (0x8100)'''
					element = Ether(element_bin)
				else:
					print ('\033[31mSorry: The hexdump collected from '+self.dst_host+', FPC'+trap_fpc_pes[int(choice)][0]+' is not IP/IPv6 or Ethernet:\033[0m')
					print(element)
					dev.close()
					quit()
				element.show2()
		dev.close()

	''' Trapping CTRL+C.
		If jsample is enabled and user aborts, we have a problem, so I dont allow abort.'''
	def signal_handler(self, signal, frame):
        	print('\033[31mCtrl+C not possible while JSAMPLE is enabled. Wait for JSAMPLE to be disabled !!!\033[0m')
        	# DO NOT EXIT AT THIS POINT. IF JSAMPLE WAS ENABLED AND USER QUITS ACCIDENTALLY, IT CAN POTENTIALLY IMPACT THE LINE CARD.
        	#sys.exit(0)
	''' Traps Ctrl+C for a graceful exit. '''
	def signal_handler_quit(self, signal, frame):
        	print('Exiting.')
        	sys.exit(0)

	''' Opens pyez device connection '''
	def dev_connection(self):
		try:
		    dev = Device(host=args.j, user=self.username, passwd=self.password, port='22', gather_facts=True)
		    dev.open(normalize=False)
		    dev.timeout = 30
		    return dev
		except ConnectError as err:
		    print("Cannot connect to device, code exiting")
		    sys.exit(-1)
		except AttributeError as err:
			print (err)
			sys.exit(-1)

	def rpc_get_syslog_payload(self, dev, fpc, pfe, trapcode):
		self.fdebug("Running jsample on FPC"+fpc+"/PFE"+pfe+"/TRAPCODE"+trapcode+" and retrieving syslog buffer (full).", facility='DEBUG')
		
		# Trap CTRL+C
		signal.signal(signal.SIGINT, self.signal_handler)
		# Enable jsample
		send_pfe_jsample_enable = self.req_pfe_command(dev, fpc, "set jsample pfe "+pfe+" trapcode "+trapcode+" enable sample-id 5 enable")
		if send_pfe_jsample_enable is not False:
			alert_enable = True
		self.fdebug("send_pfe_jsample_enable:"+send_pfe_jsample_enable.text.strip(), facility='DEBUG')

		send_pfe_debug = self.req_pfe_command(dev, fpc, 'debug expr-if trace host clog rx "trap '+trapcode+';len 90;count 5"')
		self.fdebug("send_pfe_debug:"+send_pfe_debug.text.strip(), facility='DEBUG')

		# Sleep 5 seconds before disabling jsample.
		sleep(5)
		send_pfe_jsample_disable 	= self.req_pfe_command(dev, fpc, 'set jsample pfe '+pfe+' trapcode '+trapcode+' enable sample-id 5 disable')
		if send_pfe_jsample_disable is False and alert_enable is True:
			print ('JSAMPLE WAS ENABLED AND DISABLE FAILED TRYING ONE MORE TIME.')
			if self.req_pfe_command(dev, fpc, 'set jsample pfe '+pfe+' trapcode '+trapcode+' enable sample-id 5 disable') is not True:
				print ('(DONT PANIC) JSAMPLE WAS ENABLED AND DISABLE FAILED SECOND TIME. SAVE THE OUTPUT AND ALERT JUNIPER NETWORKS TEAM.')
			else:
				send_pfe_jsample_disable = False			
		else:
			print ('\033[32mJSAMPLE ENABLE/DISABLE SUCCESSFUL. YOU SHOULD SEE IFD AND PACKET(S) DECODED BELOW:\033[0m')

		self.fdebug("send_pfe_jsample_disable:"+send_pfe_jsample_disable.text.strip(), facility='DEBUG')

		send_pfe_syslog = self.req_pfe_command(dev, fpc, 'show syslog messages')
		send_pfe_syslog = send_pfe_syslog.text
		send_pfe_syslog = send_pfe_syslog.replace('\n', ' ').replace('\r', '')

		send_pfe_syslog = re.findall(r'(?:PAYLOAD\(0-.{3,4}:([a-f0-9\ ]*))|(?:ig_gportid:([a-f0-9]{2,}))', send_pfe_syslog, flags=0)
		self.fdebug(str(send_pfe_syslog), facility='DEBUG')
		gbuffer_a = []
		for i in send_pfe_syslog:
			for a in i:
				if a != "":
					#if re.match('^..$', a, flags=0): # IFD Index hex
					if len(str(a)) in range (2,4):
						gbuffer_a.append(self.rpc_get_ifd_index(dev,a))
					else:
						gbuffer_a.append(a.replace(' ',''))
		return gbuffer_a

	def rpc_get_ifd_index(self,dev,index_hex):
		try:
			ifd_index = int(str(index_hex), 16)
			ifd_output = dev.rpc.get_interface_information(level_extra='terse', ifd_index=str(ifd_index), normalize=True)
		except SyntaxError as err:
			return False
		ifd = ifd_output.xpath('physical-interface/name')[0].text
		ifd_parent = ifd_output.xpath('physical-interface/logical-interface/address-family/ae-bundle-name')[0].text
		return [ifd, ifd_parent]
	''' Check which FPCs are online and are in fpc_whitelist. This script does not work on PTX5k gen1/gen2 FPCs.'''
	def rpc_get_online_fpc(self, dev):
		global validated_platforms
		#print (validated_platforms[self.hwModel][1])
		try: 
			rpcFpc = dev.rpc.get_pic_information(normalize=True)
			onlineFpc = rpcFpc.findall("fpc[state='Online']/slot")
			online_slots = []
			for onlineFpcSlot in onlineFpc:
				if rpcFpc.xpath('fpc[slot="'+str(onlineFpcSlot.text)+'"]/description')[0].text in validated_platforms[self.hwModel][1]: online_slots.append(onlineFpcSlot.text)
			return online_slots
		except Exception as err:
			print ("Cannot run RPC on remote device: {0}".format(err))
			return False

	''' Returns list of data errors and normal discards for all fpcs in "slots".'''
	def rpc_check_online_fpcs_data_error(self, dev, slots):
		try:
			drops_list = {}
			for slot in slots:
				rpcFpc = dev.rpc.get_pfe_statistics(fpc=slot, normalize=True)
				data_error = rpcFpc.xpath("pfe-hardware-discard-statistics/data-error-discard")[0].text
				bad_route = rpcFpc.xpath("pfe-hardware-discard-statistics/bad-route-discard")[0].text
				drops_list[slot] = (data_error,bad_route)
				self.fdebug('Checking FPC '+slot+' data errors: SUCCESS.', facility='DEBUG')
			sleep(2)
			return drops_list
		except Exception as err:
			print (inspect.stack()[0][3]+"():Error running rpcs: {0}".format(err))
			sys.exit(1)

	def check_data_error_deltas(self, dev, slots):
		data_errors1 = self.rpc_check_online_fpcs_data_error(dev, slots)
		data_errors2 = self.rpc_check_online_fpcs_data_error(dev, slots)

		data_error_fpcs = []
		# data_errors1 and 2 contain list of "data errors" and "normal discards" (aka bad-route-discards)
		# If DE or ND delta is higher than 10, we proceed.
		for slot in slots:
			if int(data_errors2[slot][0])-int(data_errors1[slot][0]) > 10 or int(data_errors2[slot][1])-int(data_errors1[slot][1]) > 10:
				data_error_fpcs.append(slot)
				print('\033[32mFPC slots that have normal discards / data errors: '+str(data_error_fpcs)+'\033[0m')
				return data_error_fpcs
			else:
				return False

	def check_fpc_trap_drops(self, dev, de_slots):
		global allowed_trap_codes
		fpc_pe_trap = []
		for fpc_slot in de_slots:
			self.fdebug('Checking trapstats on FPC'+fpc_slot)
			traps = dev.rpc.request_pfe_execute(target = str('fpc'+fpc_slot), command = "show pechip trapstats", normalize=False)
			output = traps.text
			for s in output.splitlines():
				#matches = re.findall(pattern, string, flags=0)
				#print ("Line PE TRAPS:"+str(s))
				try:
					match = re.findall(r'^\s+([0-9]+)\s+\(\s+([0-9]{3})\)\s+([^\s]+)\s+([0-9]+)\s+([0-9]+)$', s)[0]
					#print ('Match: '+str(match))
					#if int(match[-1]) > 10 and int(match[1]) in allowed_trap_codes:
					if int(match[-1]) > 0 and int(match[1]) in allowed_trap_codes:
						#fpc_pe_trap[fpc_slot] = [match[0], match[1], match[2]]
						fpc_pe_trap.append((fpc_slot, match[0], match[1], match[2]))
						self.fdebug('FPC'+fpc_slot+'/PE'+match[0]+"\t"+match[2]+' ('+match[1]+")\t trapcode has rate \033[32m"+match[-1]+'pps. Troubleshooting.\033[0m', facility='DEBUG')
					else:
						self.fdebug('FPC'+fpc_slot+'/PE'+match[0]+"\t"+match[2]+' ('+match[1]+") \t trapcode has rate "+match[-1]+'pps. Ignoring.', facility='DEBUG')

				except IndexError:
					continue
		#print (str(fpc_pe_trap))
		if len(fpc_pe_trap) > 0:
			return fpc_pe_trap
		else:
			return False

	def check_is_fpc_30C(dev, slot):
	    '''
	    function to check if a given fpc is 30C or not 
	    >>> is_fpc_30C(int) -> bool
	    >>> is_fpc_30C(0) -> True 
	    >>> is_fpc_30C(8) -> False   
	    '''
	    fpcPicStatus = dev.rpc.get_pic_information(slot=slot)
	    fpcString = str(fpcNumber)
	    searchStr = './/fpc[slot="'+fpcString+'"]/description'
	    if fpcPicStatus.findtext(searchStr):
	        return 'LC1101' in fpcPicStatus.findtext(searchStr)
	    else: 
	        return False
	''' Check if it's a CSIM validated platform/version. '''
	def check_valid_platform (self, dev): 
	    global validated_platforms
	    swInfo = dev.rpc.get_software_information()
	    hwModel = swInfo.findtext("./product-model")
	    self.hwModel = hwModel
	    hwVersion = swInfo.xpath('junos-version')[0].text
	    hostName = swInfo.findtext("./host-name").split('-re')[0].strip()

	    valid_version = validated_platforms.get(hwModel, None)
	    if valid_version is None:
	    	return False
	    for i in valid_version:
		    if re.match('^'+str(i), hwVersion, flags=0):
		    	return True
	    return False

	''' Apparently pyez dev.cli is for debugging purposes and pyez is not happy about using it.
		Keep it here for reference.'''
	def run_cli_command(self, dev, cmd):
		try:
			return dev.cli(cmd)
		except:
			print ('Could not execute RPC CLI command. Check debug (-d) or contact Juniper Networks  account team.'+err)

	''' Runs PFE commands. It accepts dev connection, fpc#, command as input
		It returns element if true or false if rpc fails. This function should not quit
		in order to alert operator if jsample enable is ok, but disable not ok.'''
	def req_pfe_command(self, dev, fpc, cmd):
		try:
			result = dev.rpc.request_pfe_execute(target=str('fpc'+fpc), command=cmd, normalize=False)
			return result
		except Exception as err:
			print ('Could not execute RPC PFE command. Check debug (-d) or contact Juniper Networks account team.'+err)
			return False
			# If jsample is enabled and other PFE commands fail, we want to know, to manually disable it. So DO NOT QUIT(), but return FALSE !!!
			#quit() #Leave me here for display.

	''' Debugging function.
		Debugs to output only if -d flag is given to via cli.'''
	def fdebug(self,message, facility='DEBUG'):
		if self.debug:
			print(str(facility)+':'+str(message))

	''' Converts hex string into packet bytes
		for scapy processing '''
	def hex_to_pkt(self,hex_s):
		tmp = re.sub('[ \t]', '', hex_s).strip()
		return bytearray.fromhex(tmp)
		#return bytes.fromhex(tmp)

if __name__ == "__main__":
	go = main(args)
