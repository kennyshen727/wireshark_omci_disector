--[[ 
   Wireshark dissector for ITU-T G984.4 and G988 OMCI frames.
   Copyright (C) 2012 Technicolor 
   Authors:
   Dirk Van Aken (dirk.vanaken@technicolor.com),
   Olivier Hardouin (olivier.hardouin@technicolor.com)

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; version 2
   of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 
   Description:
   Wireshark dissector for ONT Management and Control Interface (OMCI) protocol (ITU-T G984.4, ITU-T G988)
   This protocol is used on Gigabit Passive Optical Network (GPON) between Optical Line Termition (OLT, the network side) and Optical Network Termination (ONT, the end user side) units.
   This is management protocol used to configure services (like Ethernet, QoS, Video overlay, Tx/Rx control) on the ONT.
   The dissector applies on UDP or Ethernet packet that contains a copy of OMCI data going between ONT and OLT as explained in appendix III of ITU-T G988
  
   Links that were used to create this dissector:
   General presentation about WS dissector in Lua: http://sharkfest.wireshark.org/sharkfest.09/DT06_Bjorlykke_Lua%20Scripting%20in%20Wireshark.pdf
   Standard Wireshark dissector: http://www.wireshark.org/docs/wsug_html_chunked/wslua_dissector_example.html
   Lua Support in Wireshark: http://www.wireshark.org/docs/wsug_html_chunked/wsluarm.html
   Nice Wireshark dissector example: http://thomasfischer.biz/?p=175
   Another nice Wireshark dissector example: http://code.google.com/p/eathena/source/browse/devel/FlavioJS/athena.lua?r=9341
  
   The dissector binary to hexadecimal conversion, module available at http://www.dialectronics.com/Lua/code/BinDecHex.shtml
  
   Note from the author:
   *) Not all ME classes described in the OMCI standards are supported in this dissector (any support to complete the list is very welcome)
   *) This implementation is the first LUA SW written by the author. It (certainly) could be more efficient (any comment is welcome) 

--]]

require "BinDecHex"

-- Create a new dissector
omciproto = Proto ("omci", "OMCI Protocol")

-- init function
function omciproto.init()
end

local msgtype_meta = {
  __index = function(t, k)   
    if k < 4 or k > 28 then
      return "Reserved"
    end
  end
}

result_code = 0

local msgtype = {
	[4]="Create",
	[5]="Create Complete Connection",
	[6]="Delete",
	[7]="Delete Complete Connection",
	[8]="Set",
	[9]="Get",
	[10]="Get Complete Connection",
	[11]="Get All Alarms",
	[12]="Get All Alarms Next",
	[13]="MIB Upload",
	[14]="MIB Upload Next",
	[15]="MIB Reset",
	[16]="Alarm",
	[17]="Attribute Value Change",
	[18]="Test",
	[19]="Start Software Download",
	[20]="Download Section",
	[21]="End Software Download",
	[22]="Activate Software",
	[23]="Commit Software",
	[24]="Synchronize Time",
	[25]="Reboot",
	[26]="Get Next",
	[27]="Test Result",
	[28]="Get Current Data",
	[29]="Set Table"
}
setmetatable(msgtype, msgtype_meta)

local msg_result_meta = {
  __index = function(t, k)   
    if k == 7 or k == 8 or k > 9 then
      return "Unknown"
    end
  end
}

local msg_result= {
	[0] = "Command processed successfully",
	[1] = "Command processing error",
	[2] = "Command not supported",
	[3] = "Command parameter error",
	[4] = "Unknown managed entity",
	[5] = "Unknown managed entity instance",
	[6] = "Device busy",
    [7] = "instance exists",
	[9] = "Attribute failed or unknown"
}
setmetatable(msg_result, msg_result_meta)

local syncTime_result_meta = {
  __index = function(t, k)   
    if  k > 1 then
      return "Unknown"
    end
  end
}

local syncTime_success_result= {
	[0] = "15 min tick boundary set successfully",
	[1] = "Date and 15 min tick boundary set successfully "
}
setmetatable(syncTime_success_result, syncTime_result_meta)


local test_message_name = {}
local test_message_name_meta = {
	__index = function(t, k)
		if k >= 0 and k <= 6 then
			return "Reserved for future use"
		elseif k == 7 then
			return "Self test"
		elseif k > 7 and k <=255 then 
			return "Vendor specific" 
		else
			return "***ERROR: Not a Test ID*** (" .. k .. ")"
		end
	end
}
setmetatable(test_message_name, test_message_name_meta)

local mt2 = {
  __index = function(t2, k)   
	local returntable = {}
	if k >= 172 and k <= 239 then
		returntable.me_class_name= "Reserved for future B-PON managed entities"
	elseif k >= 240 and k <= 255 then
		returntable.me_class_name= "Reserved for vendor-specific managed entities"
   	elseif k >= 343 and k <= 65279 then 
		returntable.me_class_name= "Reserved for future standardization" 
	elseif k >= 65280 and k <= 65535 then 
		returntable.me_class_name= "Reserved for vendor-specific use"
	else
		returntable.me_class_name= "***TBD*** (" .. k .. ")"
    end
	return returntable
  end
}

local omci_def = {
[2] = { me_class_name = "ONT Data",
	{ attname="MIB Data Sync", length=1, setbycreate=false }},

[5] = { me_class_name = "Cardholder",
	{ attname="Actual Plug-in Unit Type", length=1, setbycreate=false },
	{ attname="Expected Plug-in Unit Type", length=1, setbycreate=false },
	{ attname="Expected Port Count", length=1, setbycreate=false },
	{ attname="Expected Equipment Id", length=20, setbycreate=false },
	{ attname="Actual Equipment Id", length=20, setbycreate=false },
	{ attname="Protection Profile Pointer", length=1, setbycreate=false },
	{ attname="Invoke Protection Switch", length=1, setbycreate=false },
	{ attname="Alarm-reporting control (ARC)", length=1, setbycreate=false },
	{ attname="ARC interval", length=1, setbycreate=false }	},
	

[6] = { me_class_name = "Circuit Pack",
	{ attname="Type", length=1, setbycreate=true },
	{ attname="Number of ports", length=1, setbycreate=false },
	{ attname="Serial Number", length=8, setbycreate=false },
	{ attname="Version", length=14, setbycreate=false },
	{ attname="Vendor Id", length=4, setbycreate=false },
	{ attname="Administrative State", length=1, setbycreate=true },
	{ attname="Operational State", length=1, setbycreate=false },
	{ attname="Bridged or IP Ind", length=1, setbycreate=false },
	{ attname="Equipment Id", length=20, setbycreate=false },
	{ attname="Card Configuration", length=1, setbycreate=true },
	{ attname="Total T-CONT Buffer Number", length=1, setbycreate=false },
	{ attname="Total Priority Queue Number", length=1, setbycreate=false },
	{ attname="Total Traffic Scheduler Number", length=1, setbycreate=false },
	{ attname="Power Shed Override", length=4, setbycreate=false }},

[7] = { me_class_name = "Software Image",
	{ attname="Version", length=14, setbycreate=false },
	{ attname="Is committed", length=1, setbycreate=false },
	{ attname="Is active", length=1, setbycreate=false },
	{ attname="Is valid", length=1, setbycreate=false },
	{ attname="Product code", length=25, setbycreate=false },
	{ attname="Image hash", length=16, setbycreate=false }},

[11] = { me_class_name = "PPTP Ethernet UNI",
	{attname="Expected Type",			length=1, setbycreate=false},
	{attname="Sensed Type",				length=1, setbycreate=false},
	{attname="Auto Detection Configuration",	length=1, setbycreate=false},
	{attname="Ethernet Loopback Configuration",	length=1, setbycreate=false},
	{attname="Administrative State",		length=1, setbycreate=false},
	{attname="Operational State",			length=1, setbycreate=false},
	{attname="Configuration Ind",			length=1, setbycreate=false},
	{attname="Max Frame Size",			length=2, setbycreate=false},
	{attname="DTE or DCE",				length=1, setbycreate=false},
	{attname="Pause Time",				length=2, setbycreate=false},
	{attname="Bridged or IP Ind",			length=1, setbycreate=false},
	{attname="ARC",					length=1, setbycreate=false},
	{attname="ARC Interval",			length=1, setbycreate=false},
	{attname="PPPoE Filter",			length=1, setbycreate=false},
	{attname="Power Control",			length=1, setbycreate=false}},

[24] = { me_class_name = "Ethernet PM History Data",
	{ attname="Interval End Time", length=1, setbycreate=false },
	{ attname="Threshold Data 1/2 Id", length=2, setbycreate=true },
	{ attname="FCS errors Drop events", length=4, setbycreate=false },
	{ attname="Excessive Collision Counter", length=4, setbycreate=false },
	{ attname="Late Collision Counter", length=4, setbycreate=false },
	{ attname="Frames too long", length=4, setbycreate=false },
	{ attname="Buffer overflows on Receive", length=4, setbycreate=false },
	{ attname="Buffer overflows on Transmit", length=4, setbycreate=false },	
	{ attname="Single Collision Frame Counter", length=4, setbycreate=false },	
	{ attname="Multiple Collisions Frame Counter", length=4, setbycreate=false },
	{ attname="SQE counter", length=4, setbycreate=false },
	{ attname="Deferred Transmission Counter", length=4, setbycreate=false },
	{ attname="Internal MAC Transmit Error Counter", length=4, setbycreate=false },
	{ attname="Carrier Sense Error Counter", length=4, setbycreate=false },
	{ attname="Alignment Error Counter", length=4, setbycreate=false },
	{ attname="Internal MAC Receive Error Counter", length=4, setbycreate=false}},

[44] = { me_class_name = "Vendor Specific",
	{ attname="Sub-Entity", length=1, setbycreate=true },
	subentity_attr = {}},
		
[45] = { me_class_name = "MAC Bridge Service Profile",
	{ attname="Spanning tree ind", length=1, setbycreate=true },
	{ attname="Learning ind", length=1, setbycreate=true },
	{ attname="Port bridging ind", length=1, setbycreate=true },
	{ attname="Priority", length=2, setbycreate=true },
	{ attname="Max age", length=2, setbycreate=true },
	{ attname="Hello time", length=2, setbycreate=true },
	{ attname="Forward delay", length=2, setbycreate=true },
	{ attname="Unknown MAC address discard", length=1, setbycreate=true },
	{ attname="MAC learning depth", length=1, setbycreate=true }},

[46] = { me_class_name = "MAC bridge configuration data",
	{ attname="Bridge MAC address", length=6, setbycreate=false },
	{ attname="Bridge priority", length=2, setbycreate=false },
	{ attname="Designated root", length=8, setbycreate=false },
	{ attname="Root path cost", length=4, setbycreate=false },
	{ attname="Bridge port count", length=1, setbycreate=false },
	{ attname="Root port num", length=2, setbycreate=false },
	{ attname="Hello time", length=2, setbycreate=false },
	{ attname="Forward delay", length=2, setbycreate=false }},

[47] = { me_class_name = "MAC bridge port configuration data",
	{ attname="Bridge id pointer", length=2, setbycreate=true },
	{ attname="Port num", length=1, setbycreate=true },
	{ attname="TP type", length=1, setbycreate=true },
	{ attname="TP pointer", length=2, setbycreate=true },
	{ attname="Port priority", length=2, setbycreate=true },
	{ attname="Port path cost", length=2, setbycreate=true },
	{ attname="Port spanning tree ind", length=1, setbycreate=true },
	{ attname="Encapsulation method", length=1, setbycreate=true },
	{ attname="LAN FCS ind", length=1, setbycreate=true },
	{ attname="Port MAC address", length=6, setbycreate=false },
	{ attname="Outbound TD pointer", length=2, setbycreate=false },
	{ attname="Inbound TD pointer", length=2, setbycreate=false },
	{ attname="MAC learning depth", length=1, setbycreate=true }},	

[48] = { me_class_name = "MAC bridge port designation data",
	{ attname="Designated bridge root cost port", length=24, setbycreate=false },
	{ attname="Port state", length=1, setbycreate=false }},

[49] = { me_class_name = "MAC bridge port filter table data",
	{ attname="MAC filter table", length=8, setbycreate=false }},
	
[50] = { me_class_name = "MAC bridge port bridge table data",
	{ attname="Bridge table", length=8, setbycreate=false }},

[51] = { me_class_name = "MAC Bridge PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Bridge learning entry discard count", length=4, setbycreate=false }},

[52] = { me_class_name = "MAC Bridge Port PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Forwarded frame counter", length=4, setbycreate=false },	
	{ attname="Delay exceeded discard counter", length=4, setbycreate=false },	
	{ attname="MTU exceeded discard counter", length=4, setbycreate=false },	
	{ attname="Received frame counter", length=4, setbycreate=false },	
	{ attname="Received and discarded counter", length=4, setbycreate=false }},

[53] = { me_class_name = "Physical path termination point POTS UNI",
	{ attname="Administrative state", length=1, setbycreate=false },
	{ attname="Deprecated", length=2, setbycreate=false },
	{ attname="ARC", length=1, setbycreate=false },	
	{ attname="ARC interval", length=1, setbycreate=false },	
	{ attname="Impedance", length=1, setbycreate=false },	
	{ attname="Transmission path", length=1, setbycreate=false },
	{ attname="Rx gain", length=1, setbycreate=false },	
	{ attname="Tx gain", length=1, setbycreate=false },	
	{ attname="Operational state", length=1, setbycreate=false },	
	{ attname="Hook state", length=1, setbycreate=false },	
	{ attname="POTS holdover time", length=2, setbycreate=false },
	{ attname="Nominal feed voltage", length=1, setbycreate=false },
	{ attname="Loss of softswitch", length=1, setbycreate=false }},

[58] = { me_class_name = "Voice service profile",
	{ attname="Announcement type", length=1, setbycreate=true },
	{ attname="Jitter target", length=2, setbycreate=true },
	{ attname="Jitter buffer max", length=2, setbycreate=true },	
	{ attname="Echo cancel ind", length=1, setbycreate=true },
	{ attname="PSTN protocol variant", length=2, setbycreate=true },
	{ attname="DTMF digit levels", length=2, setbycreate=true },
	{ attname="DTMF digit duration", length=2, setbycreate=true },
	{ attname="Hook flash minimum time", length=2, setbycreate=true },
	{ attname="Hook flash maximum time", length=2, setbycreate=true },
	{ attname="Tone pattern table", length=20, setbycreate=false },
	{ attname="Tone event table", length=7, setbycreate=false },
	{ attname="Ringing pattern table", length=5, setbycreate=false },
	{ attname="Ringing event table", length=7, setbycreate=false }},

[78] = { me_class_name = "VLAN tagging operation configuration data",
	{attname="Upstream VLAN tagging operation mode", length=1, setbycreate=true},
	{attname="Upstream VLAN tag TCI value", length=2, setbycreate=true},
	{attname="Downstream VLAN tagging operation mode",	length=1, setbycreate=true},
	{attname="Association type", length=1, setbycreate=true},
	{attname="Associated ME pointer", length=2, setbycreate=true}},

[79] = { me_class_name = "MAC bridge port filter preassign table",
	{ attname="IPv4 multicast filtering", length=1, setbycreate=false },
	{ attname="IPv6 multicast filtering", length=1, setbycreate=false },
	{ attname="IPv4 broadcast filtering", length=1, setbycreate=false },
	{ attname="RARP filtering", length=1, setbycreate=false },
	{ attname="IPX filtering", length=1, setbycreate=false },
	{ attname="NetBEUI filtering", length=1, setbycreate=false },
	{ attname="AppleTalk filtering", length=1, setbycreate=false },
	{ attname="Bridge management information filtering", length=1, setbycreate=false },
	{ attname="ARP filtering", length=1, setbycreate=false }},

[82] = { me_class_name = "PPTP Video UNI",
	{attname="Administrative State", length=1, setbycreate=false},
	{attname="Operational State", length=1, setbycreate=false},
	{attname="ARC",	length=1, setbycreate=false},
	{attname="ARC Interval", length=1, setbycreate=false},
	{attname="Power Control", length=1, setbycreate=false}},
	
[84] = { me_class_name = "VLAN tagging filter data",
	{attname="VLAN filter list", length=24, setbycreate=true},
	{attname="Forward operation", length=1, setbycreate=true},
	{attname="Number of entries",	length=1, setbycreate=true}},

[89] = { me_class_name = "Ethernet PM History Data 2",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="PPPoE filtered frame counter", length=4, setbycreate=false }},
	
[90] = { me_class_name = "PPTP Video ANI",
	{attname="Administrative State", length=1, setbycreate=false},
	{attname="Operational State", length=1, setbycreate=false},
	{attname="ARC",	length=1, setbycreate=false},
	{attname="ARC Interval", length=1, setbycreate=false},
	{attname="Frequency Range Low", length=1, setbycreate=false},
	{attname="Frequency Range High", length=1, setbycreate=false},
	{attname="Signal Capability", length=1, setbycreate=false},
	{attname="Optical Signal Level", length=1, setbycreate=false},
	{attname="Pilot Signal Level", length=1, setbycreate=false},
	{attname="Signal Level min", length=1,	setbycreate=false},
	{attname="Signal Level max", length=1,	setbycreate=false},
	{attname="Pilot Frequency", length=4,	setbycreate=false},
	{attname="AGC Mode", length=1,	setbycreate=false},
	{attname="AGC Setting", length=1,	setbycreate=false},	
	{attname="Video Lower Optical Threshold", length=1, setbycreate=false},
	{attname="Video Upper Optical Threshold", length=1, setbycreate=false}},
 
 [130] = { me_class_name = "802.1P Mapper Service Profile",
	{attname="TP Pointer",					length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 0",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 1",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 2",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 3",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 4",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 5",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 6",	length=2,  setbycreate=true},
	{attname="Interwork TP pointer for P-bit priority 7",	length=2,  setbycreate=true},
	{attname="Unmarked frame option:",		length=1,  setbycreate=true},
	{attname="DSCP to P-bit mapping",		length=24, setbycreate=false},
	{attname="Default P-bit marking",		length=1,  setbycreate=true},
	{attname="TP Type:",					length=1,  setbycreate=true}},

[131] = { me_class_name = "OLT-G",
	{attname="OLT vendor id",					length=4,  setbycreate=false},
	{attname="Equipment id",	length=20,  setbycreate=false},
	{attname="OLT version",	length=14,  setbycreate=false},
	{attname="Time of day information",	length=14,  setbycreate=false}},
				
[133] = { me_class_name = "ONU Power Shedding",
	{ attname="Restore power timer reset interval", length=2, setbycreate=false },
	{ attname="Data class shedding interval", length=2, setbycreate=false },
	{ attname="Voice class shedding interval", length=2, setbycreate=false },
	{ attname="Video overlay class shedding interval", length=2, setbycreate=false },
	{ attname="Video return class shedding interval", length=2, setbycreate=false },
	{ attname="DSL class shedding interval", length=2, setbycreate=false },
	{ attname="ATM class shedding interval", length=2, setbycreate=false },
	{ attname="CES class shedding interval", length=2, setbycreate=false },
	{ attname="Frame class shedding interval", length=2, setbycreate=false },
	{ attname="SONET class shedding interval", length=2, setbycreate=false },
	{ attname="Shedding status", length=2, setbycreate=false }},

[134] = { me_class_name = "IP host config data",
	{ attname="IP options", length=1, setbycreate=false },
	{ attname="MAC address", length=6, setbycreate=false },
	{ attname="Onu identifier", length=25, setbycreate=false },
	{ attname="IP address", length=4, setbycreate=false },
	{ attname="Mask", length=4, setbycreate=false },
	{ attname="Gateway", length=4, setbycreate=false },
	{ attname="Primary DNS", length=4, setbycreate=false },
	{ attname="Secondary DNS", length=4, setbycreate=false },
	{ attname="Current address", length=4, setbycreate=false },
	{ attname="Current mask", length=4, setbycreate=false },
	{ attname="Current gateway", length=4, setbycreate=false },
	{ attname="Current primary DNS", length=4, setbycreate=false },
	{ attname="Current secondary DNS", length=4, setbycreate=false },
	{ attname="Domain name", length=25, setbycreate=false },
	{ attname="Host name", length=25, setbycreate=false },
	{ attname="Relay agent options", length=2, setbycreate=false }},
	
[135] = { me_class_name = "IP host performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="ICMP errors", length=4, setbycreate=false },
	{ attname="DNS errors", length=4, setbycreate=false },
	{ attname="DHCP timeouts", length=2, setbycreate=false },
	{ attname="IP address conflict", length=2, setbycreate=false },
	{ attname="Out of memory", length=2, setbycreate=false },
	{ attname="Internal error", length=2, setbycreate=false }},
	
[136] = { me_class_name = "TCP/UDP config data",
	{ attname="Port id", length=2, setbycreate=true },
	{ attname="Protocol", length=1, setbycreate=true },
	{ attname="TOS/diffserv field", length=1, setbycreate=true },
	{ attname="IP host pointer", length=2, setbycreate=true }},
	
[137] = { me_class_name = "Network address",
	{ attname="Security pointer", length=2, setbycreate=true },
	{ attname="Address pointer", length=2, setbycreate=true }},

[138] = { me_class_name = "VoIP config data",
	{ attname="Available signalling protocols", length=1, setbycreate=false },
	{ attname="Signalling protocol used", length=1, setbycreate=false },
	{ attname="Available VoIP configuration methods", length=4, setbycreate=false },
	{ attname="VoIP configuration method used", length=1, setbycreate=false },
	{ attname="VoIP configuration address pointer", length=2, setbycreate=false },
	{ attname="VoIP configuration state", length=1, setbycreate=false },
	{ attname="Retrieve profile", length=1, setbycreate=false },
	{ attname="Profile version", length=25, setbycreate=false }},

[139] = { me_class_name = "VoIP voice CTP",
	{ attname="User protocol pointer", length=2, setbycreate=true },
	{ attname="PPTP pointer", length=2, setbycreate=true },
	{ attname="VoIP media profile pointer", length=2, setbycreate=true },
	{ attname="Signalling code", length=1, setbycreate=true }},

[140] = { me_class_name = "Call control performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Call setup failures", length=4, setbycreate=false },
	{ attname="Call setup timer", length=4, setbycreate=false },
	{ attname="Call terminate failures", length=4, setbycreate=false },
	{ attname="Analog port releases", length=4, setbycreate=false },
	{ attname="Analog port off-hook timer", length=4, setbycreate=false }},

[141] = { me_class_name = "VoIP line status",
	{ attname="Voip codec used", length=2, setbycreate=false },
	{ attname="Voip voice server status", length=1, setbycreate=false },
	{ attname="Voip port session type", length=1, setbycreate=false },
	{ attname="Voip call 1 packet period", length=2, setbycreate=false },
	{ attname="Voip call 2 packet period", length=2, setbycreate=false },
	{ attname="Voip call 1 dest addr", length=25, setbycreate=false },
	{ attname="Voip call 2 dest addr", length=25, setbycreate=false },
	{ attname="Voip line state", length=1, setbycreate=false },
	{ attname="Emergency call status", length=1, setbycreate=false }},
	
[142] = { me_class_name = "VoIP media profile",
	{ attname="Fax mode", length=1, setbycreate=true },
	{ attname="Voice service profile pointer", length=2, setbycreate=true },
	{ attname="Codec selection (1st order)", length=1, setbycreate=true },
	{ attname="Packet period selection (1st order)", length=1, setbycreate=true },
	{ attname="Silence suppression (1st order)", length=1, setbycreate=true },
	{ attname="Codec selection (2nd order)", length=1, setbycreate=true },
	{ attname="Packet period selection (2nd order)", length=1, setbycreate=true },
	{ attname="Silence suppression (2nd order)", length=1, setbycreate=true },
	{ attname="Codec selection (3rd order)", length=1, setbycreate=true },
	{ attname="Packet period selection (3rd order)", length=1, setbycreate=true },
	{ attname="Silence suppression (3rd order)", length=1, setbycreate=true },
	{ attname="Codec selection (4th order)", length=1, setbycreate=true },
	{ attname="Packet period selection (4th order)", length=1, setbycreate=true },
	{ attname="Silence suppression (4th order)", length=1, setbycreate=true },
	{ attname="OOB DTMF", length=1, setbycreate=true },
	{ attname="RTP profile pointer", length=2, setbycreate=true }},

[143] = { me_class_name = "RTP profile data",
	{ attname="Local port min", length=2, setbycreate=true },
	{ attname="Local port max", length=2, setbycreate=true },
	{ attname="DSCP mark", length=1, setbycreate=true },
	{ attname="Piggyback events", length=1, setbycreate=true },
	{ attname="Tone events", length=1, setbycreate=true },
	{ attname="DTMF events", length=1, setbycreate=true },
	{ attname="CAS events", length=1, setbycreate=true }},

[144] = { me_class_name = "RTP performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="RTP errors", length=4, setbycreate=false },
	{ attname="Packet loss", length=4, setbycreate=false },
	{ attname="Maximum jitter", length=4, setbycreate=false },
	{ attname="Maximum time between RTCP packets", length=4, setbycreate=false },
	{ attname="Buffer underflows", length=4, setbycreate=false },
	{ attname="Buffer overflows", length=4, setbycreate=false }},

[145] = { me_class_name = "Network dial plan table",
	{ attname="Dial plan number", length=2, setbycreate=false },
	{ attname="Dial plan table max size", length=2, setbycreate=true },
	{ attname="Critical dial timeout", length=2, setbycreate=true },
	{ attname="Partial dial timeout", length=2, setbycreate=true },
	{ attname="Dial plan format", length=1, setbycreate=true },
	{ attname="Dial plan table", length=30, setbycreate=false },
	{ attname="Dial plan id", length=1, setbycreate=false },
	{ attname="Action", length=1, setbycreate=false },
    { attname="Dial plan token", length=28, setbycreate=false }},

[146] = { me_class_name = "VoIP application service profile",
	{ attname="CID features", length=1, setbycreate=true },
	{ attname="Call waiting features", length=1, setbycreate=true },
	{ attname="Call progress or transfer features", length=2, setbycreate=true },
	{ attname="Call presentation features", length=2, setbycreate=true },
	{ attname="Direct connect feature", length=1, setbycreate=true },
	{ attname="Direct connect URI pointer", length=2, setbycreate=true },
	{ attname="Bridged line agent URI pointer", length=2, setbycreate=true },
	{ attname="Conference factory URI pointer", length=2, setbycreate=true }},

[147] = { me_class_name = "VoIP feature access codes",
	{ attname="Cancel call waiting", length=5, setbycreate=false },
	{ attname="Call hold", length=5, setbycreate=false },
	{ attname="Call park", length=5, setbycreate=false },
	{ attname="Caller ID activate", length=5, setbycreate=false },
	{ attname="Caller ID deactivate", length=5, setbycreate=false },
	{ attname="Do not disturb activation", length=5, setbycreate=false },
	{ attname="Do not disturb deactivation", length=5, setbycreate=false },
	{ attname="Do not disturb PIN change", length=5, setbycreate=false },
	{ attname="Emergency service number", length=5, setbycreate=false },
	{ attname="Intercom service", length=5, setbycreate=false },
	{ attname="Unattended/blind call transfer", length=5, setbycreate=false },
	{ attname="Attended call transfer", length=5, setbycreate=false }},

[148] = { me_class_name = "Authentication security method",
	{ attname="Validation scheme", length=1, setbycreate=false },
	{ attname="Username 1", length=25, setbycreate=false },
	{ attname="Password", length=25, setbycreate=false },
	{ attname="Realm", length=25, setbycreate=false },
	{ attname="Username 2", length=25, setbycreate=false }},

[149] = { me_class_name = "SIP config portal",
	{ attname="Configuration text table", length=1, setbycreate=false }},

[150] = { me_class_name = "SIP agent config data",
	{ attname="Proxy server address pointer", length=2, setbycreate=true },
	{ attname="Outbound proxy address pointer", length=2, setbycreate=true },
	{ attname="Primary SIP DNS", length=4, setbycreate=true },
	{ attname="Secondary SIP DNS", length=4, setbycreate=true },
	{ attname="TCP/UDP pointer", length=2, setbycreate=false },
	{ attname="SIP reg exp time", length=4, setbycreate=false },
	{ attname="SIP rereg head start time", length=4, setbycreate=false },
	{ attname="Host part URI", length=2, setbycreate=true },
	{ attname="SIP status", length=1, setbycreate=false },
	{ attname="SIP registrar", length=2, setbycreate=true },
	{ attname="Softswitch", length=4, setbycreate=true },
	{ attname="SIP response table", length=5, setbycreate=false },
	{ attname="SIP option transmit control", length=1, setbycreate=true },
	{ attname="SIP URI format", length=1, setbycreate=true },
	{ attname="Redundant SIP agent pointer", length=2, setbycreate=true }},

[151] = { me_class_name = "SIP agent performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Transactions", length=4, setbycreate=false },
	{ attname="Rx invite reqs", length=4, setbycreate=false },
	{ attname="Rx invite retrans", length=4, setbycreate=false },
	{ attname="Rx noninvite reqs", length=4, setbycreate=false },
	{ attname="Rx noninvite retrans", length=4, setbycreate=false },
	{ attname="Rx response", length=4, setbycreate=false },
	{ attname="Rx response retransmissions", length=4, setbycreate=false },
	{ attname="Rx response", length=4, setbycreate=false },
	{ attname="Tx invite reqs", length=4, setbycreate=false },
	{ attname="Tx invite retrans", length=4, setbycreate=false },
	{ attname="Tx noninvite reqs", length=4, setbycreate=false },
	{ attname="Tx noninvite retrans", length=4, setbycreate=false },
	{ attname="Tx response", length=4, setbycreate=false },
	{ attname="Tx response retransmissions", length=4, setbycreate=false }},

[152] = { me_class_name = "SIP call initiation performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Failed to connect counter", length=4, setbycreate=false },
	{ attname="Failed to validate counter", length=4, setbycreate=false },
	{ attname="Timeout counter", length=4, setbycreate=false },
	{ attname="Failure received counter", length=4, setbycreate=false },
	{ attname="Failed to authenticate counter", length=4, setbycreate=false }},

[153] = { me_class_name = "SIP user data",
	{ attname="SIP agent pointer", length=2, setbycreate=true },
	{ attname="User part AOR", length=2, setbycreate=true },
	{ attname="SIP display name", length=25, setbycreate=false },
	{ attname="Username/password", length=2, setbycreate=true },
	{ attname="Voicemail server SIP URI", length=2, setbycreate=true },
	{ attname="Voicemail subscription expiration time", length=4, setbycreate=true },
	{ attname="Network dial plan pointer", length=2, setbycreate=true },
	{ attname="Application services profile pointer", length=2, setbycreate=true },
	{ attname="Feature code pointer", length=2, setbycreate=true },
	{ attname="PPTP pointer", length=2, setbycreate=true },
	{ attname="Release timer", length=1, setbycreate=false },
	{ attname="ROH timer", length=1, setbycreate=false }},

[154] = { me_class_name = "MGC config portal",
	{ attname="Configuration text table", length=1, setbycreate=false }},

[155] = { me_class_name = "MGC config data",
	{ attname="Primary MGC", length=2, setbycreate=true },
	{ attname="Secondary MGC", length=2, setbycreate=true },
	{ attname="TCP/UDP pointer", length=2, setbycreate=true },
	{ attname="Version", length=1, setbycreate=true },
	{ attname="Message format", length=2, setbycreate=true },
	{ attname="Maximum retry time", length=2, setbycreate=false },
	{ attname="Maximum retry attempts", length=2, setbycreate=true },
	{ attname="Service change delay", length=2, setbycreate=false },
	{ attname="Termination ID base", length=25, setbycreate=false },
	{ attname="Softswitch", length=4, setbycreate=true },
	{ attname="Message ID pointer", length=2, setbycreate=true }},

[156] = { me_class_name = "MGC performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Received messages", length=4, setbycreate=false },
	{ attname="Received octets", length=4, setbycreate=false },
	{ attname="Sent messages", length=4, setbycreate=false },
	{ attname="Sent octets", length=4, setbycreate=false },
	{ attname="Protocol errors", length=4, setbycreate=false },
	{ attname="Transport losses", length=4, setbycreate=false },
	{ attname="Last detected event", length=1, setbycreate=false },
	{ attname="Last detected event time", length=4, setbycreate=false },
	{ attname="Last detected reset time", length=4, setbycreate=false }},

[157] = { me_class_name = "Large string",
	{ attname="Number of parts", length=1, setbycreate=false },
	{ attname="Part 1", length=25, setbycreate=false },
	{ attname="Part 2", length=25, setbycreate=false },
	{ attname="Part 3", length=25, setbycreate=false },
	{ attname="Part 4", length=25, setbycreate=false },
	{ attname="Part 5", length=25, setbycreate=false },
	{ attname="Part 6", length=25, setbycreate=false },
	{ attname="Part 7", length=25, setbycreate=false },
	{ attname="Part 8", length=25, setbycreate=false },
	{ attname="Part 9", length=25, setbycreate=false },
	{ attname="Part 10", length=25, setbycreate=false },
	{ attname="Part 11", length=25, setbycreate=false },
	{ attname="Part 12", length=25, setbycreate=false },
	{ attname="Part 13", length=25, setbycreate=false },
	{ attname="Part 14", length=25, setbycreate=false },
	{ attname="Part 15", length=25, setbycreate=false }},

[158] = { me_class_name = "ONT remote debug",
	{ attname="Command format", length=1, setbycreate=false },
	{ attname="Command", length=25, setbycreate=false },
	{ attname="Reply table", length=4, setbycreate=false }},

[159] = { me_class_name = "Equipment protection profile",
	{ attname="Protect slot 1,protect slot 2", length=2, setbycreate=true },
	{ attname="working slot 1,working slot 2,working slot 3,working slot 4,working slot 5,working slot 6,working slot 7,working slot 8", length=8, setbycreate=true },
	{ attname="Protect status 1,protect status 2", length=2, setbycreate=false },
	{ attname="Revertive ind", length=1, setbycreate=true },
	{ attname="Wait to restore time", length=1, setbycreate=true }},

[160] = { me_class_name = "Equipment extension package",
	{ attname="Environmental sense", length=2, setbycreate=false },
	{ attname="Contact closure output", length=2, setbycreate=false }},

[171] = { me_class_name = "Extended VLAN tagging operation configuration data",
	{ attname="Association type", length=1, setbycreate=true },
	{ attname="Received frame VLAN tagging operation table max size", length=2, setbycreate=false },
	{ attname="Input TPID", length=2, setbycreate=false },
	{ attname="Output TPID", length=2, setbycreate=false },	
	{ attname="Downstream mode", length=1, setbycreate=false },
	{ attname="Received frame VLAN tagging operation table", length=16, setbycreate=false },
	{ attname="Associated ME pointer", length=2, setbycreate=true },
	{ attname="DSCP to P-bit mapping", length=24, setbycreate=false }},
	
[256] = { me_class_name = "ONU-G",
	{ attname="Vendor Id", length=4, setbycreate=false },
	{ attname="Version", length=14, setbycreate=false },
	{ attname="Serial Nr", length=8, setbycreate=false },
	{ attname="Traffic management option", length=1, setbycreate=false },
	{ attname="Deprecated", length=1, setbycreate=false },
	{ attname="Battery backup", length=1, setbycreate=false },
	{ attname="Administrative State", length=1, setbycreate=false },
	{ attname="Operational State", length=1, setbycreate=false },
	{ attname="ONU survival time", length=1, setbycreate=false },
	{ attname="Logical ONU ID", length=24, setbycreate=false },
	{ attname="Logical password", length=12, setbycreate=false },
	{ attname="Credentials status", length=1, setbycreate=false },
	{ attname="Extended TC-layer options", length=2, setbycreate=false }},

[257] = { me_class_name = "ONT2-G",
	{ attname="Equipment id", length=20, setbycreate=false },
	{ attname="OMCC version", length=1, setbycreate=false },
	{ attname="Vendor product code", length=2, setbycreate=false },
	{ attname="Security capability", length=1, setbycreate=false },
	{ attname="Security mode", length=1, setbycreate=false },
	{ attname="Total priority queue number", length=2, setbycreate=false },
	{ attname="Total traffic scheduler number", length=1, setbycreate=false },
	{ attname="Mode", length=1, setbycreate=false },
	{ attname="Total GEM port-ID number", length=2, setbycreate=false },
	{ attname="SysUp Time", length=4, setbycreate=false },
	{ attname="Connectivity capability", length=2, setbycreate=false },
	{ attname="Current connectivity mode", length=1, setbycreate=false },
	{ attname="QoS configuration flexibility", length=2, setbycreate=false },
	{ attname="Priority queue scale factor", length=2, setbycreate=false }},

[262] = { me_class_name = "T-CONT",
	{ attname="Alloc-id", length=2, setbycreate=false },
	{ attname="Mode indicator", length=1, setbycreate=false },
	{ attname="Policy", length=1, setbycreate=false }},

[263] = { me_class_name = "ANI-G",
	{ attname="SR indication", length=1, setbycreate=false },
	{ attname="Total T-CONT number", length=2, setbycreate=false },
	{ attname="GEM block length", length=2, setbycreate=false },
	{ attname="Piggyback DBA reporting", length=1, setbycreate=false },
	{ attname="Whole ONT DBA reporting", length=1, setbycreate=false },
	{ attname="SF threshold", length=1, setbycreate=false },
	{ attname="SD threshold", length=1, setbycreate=false },
	{ attname="ARC", length=1, setbycreate=false },
	{ attname="ARC interval", length=1, setbycreate=false },
	{ attname="Optical signal level", length=2, setbycreate=false },
	{ attname="Lower optical threshold", length=1, setbycreate=false },
	{ attname="Upper optical threshold", length=1, setbycreate=false },
	{ attname="ONT response time", length=2, setbycreate=false },
	{ attname="Transmit optical level", length=2, setbycreate=false },
	{ attname="Lower transmit power threshold", length=1, setbycreate=false },
	{ attname="Upper transmit power threshold", length=1, setbycreate=false }},

[264] = { me_class_name = "UNI-G",
	{ attname="Config option status", length=2, setbycreate=false },
	{ attname="Administrative state", length=1, setbycreate=false },
	{attname="Management capability", length=1, setbycreate=false },
	{attname="Non-OMCI management identifier", length=2, setbycreate=false },
	{attname="Relay agent options", length=2, setbycreate=false }},
	
[266] = { me_class_name = "GEM interworking Termination Point",
	{ attname="GEM port network CTP connectivity pointer", length=2, setbycreate=true },
	{ attname="Interworking option", length=1, setbycreate=true },
	{ attname="Service profile pointer", length=2, setbycreate=true },
	{ attname="Interworking termination point pointer", length=2, setbycreate=true },
	{ attname="PPTP counter", length=1, setbycreate=false },
	{ attname="Operational state", length=1, setbycreate=false },
	{ attname="GAL profile pointer", length=2, setbycreate=true },
	{ attname="GAL loopback configuration", length=1, setbycreate=false }},

[267] = { me_class_name = "GEM Port PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Lost packets", length=4, setbycreate=false },
	{ attname="Misinserted packets", length=4, setbycreate=false },
	{ attname="Received packets", length=5, setbycreate=false },
	{ attname="Received blocks", length=5, setbycreate=false },
	{ attname="Transmitted blocks", length=5, setbycreate=false },
	{ attname="Impaired blocks", length=4, setbycreate=false }},

[268] = { me_class_name = "GEM Port Network CTP",
	{ attname="Port id value", length=2, setbycreate=true },
	{ attname="T-CONT pointer", length=2, setbycreate=true },
	{ attname="Direction", length=1, setbycreate=true },
	{ attname="Traffic management pointer for upstream", length=2, setbycreate=true },
	{ attname="Traffic descriptor profile pointer", length=2, setbycreate=true },
	{ attname="UNI counter", length=1, setbycreate=false },
	{ attname="Priority queue pointer for downstream", length=2, setbycreate=true },
	{ attname="Encryption state", length=1, setbycreate=false },
	{ attname="Traffic descriptor pt for downstream", length=2, setbycreate=true },
	{ attname="Encryption key ring", length=1, setbycreate=true }},

[271] = { me_class_name = "GAL TDM profile",
	{ attname="GEM frame loss integration period", length=2, setbycreate=true }},

[272] = { me_class_name = "GAL Ethernet profile",
	{ attname="Maximum GEM payload size", length=2, setbycreate=true }},

[273] = { me_class_name = "Threshold Data 1",
	{attname="Threshold value 1",	length=4,  setbycreate=true},
	{attname="Threshold value 2",	length=4,  setbycreate=true},
	{attname="Threshold value 3",	length=4,  setbycreate=true},
	{attname="Threshold value 4",	length=4,  setbycreate=true},
	{attname="Threshold value 5",	length=4,  setbycreate=true},
	{attname="Threshold value 6",	length=4,  setbycreate=true},
	{attname="Threshold value 7",	length=4,  setbycreate=true}},

[274] = { me_class_name = "Threshold Data 2",
	{attname="Threshold value 8",	length=4,  setbycreate=true},
	{attname="Threshold value 9",	length=4,  setbycreate=true},
	{attname="Threshold value 10",	length=4,  setbycreate=true},
	{attname="Threshold value 11",	length=4,  setbycreate=true},
	{attname="Threshold value 12",	length=4,  setbycreate=true},
	{attname="Threshold value 13",	length=4,  setbycreate=true},
	{attname="Threshold value 14",	length=4,  setbycreate=true}},

[275] = { me_class_name = "GAL TDM PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="GEM frame loss", length=4, setbycreate=false },
	{ attname="Buffer underflows", length=4, setbycreate=false },
	{ attname="Buffer overflows", length=4, setbycreate=false }},

[276] = { me_class_name = "GAL Ethernet PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Discarded frames", length=4, setbycreate=false }},

[277] = { me_class_name = "Priority queue-G",
	{attname="Queue Configuration Option",		length=1,  setbycreate=false},
	{attname="Maximum Queue Size",			length=2,  setbycreate=false},
	{attname="Allocated Queue Size",		length=2,  setbycreate=false},
	{attname="Discard-block Counter Reset Interval",length=2,  setbycreate=false},
	{attname="Threshold Value For Discarded Blocks Due To Buffer Overflow",	length=2,  setbycreate=false},
	{attname="Related Port",			length=4,  setbycreate=false},
	{attname="Traffic Scheduler-G Pointer",		length=2,  setbycreate=false},
	{attname="Weight",				length=1,  setbycreate=false},
	{attname="Back Pressure Operation",		length=2,  setbycreate=false},
	{attname="Back Pressure Time",			length=4,  setbycreate=false},
	{attname="Back Pressure Occur Queue Threshold",	length=2,  setbycreate=false},
	{attname="Back Pressure Clear Queue Threshold",	length=2,  setbycreate=false},
	{attname="Packet drop queue thresholds",	length=8,  setbycreate=false},
	{attname="Packet drop max_p",			length=2,  setbycreate=false},
	{attname="Queue drop w_q",			length=1,  setbycreate=false},
	{attname="Drop precedence colour marking",	length=1,  setbycreate=false}},

[278] = { me_class_name = "Traffic Scheduler-G",
	{ attname="TCONT pointer", length=2, setbycreate=false },
	{ attname="traffic shed pointer", length=2, setbycreate=false },
	{ attname="policy", length=1, setbycreate=false },
	{ attname="priority/weight", length=1, setbycreate=false }},
	
[279] = { me_class_name = "Protection data",
	{ attname="Working ANI-G pointer", length=2, setbycreate=false },
	{ attname="Protection ANI-G pointer", length=2, setbycreate=false },
	{ attname="Protection type", length=2, setbycreate=false },
	{ attname="Revertive ind", length=1, setbycreate=false },
	{ attname="Wait to restore time", length=1, setbycreate=false },
	{ attname="Switching guard time", length=2, setbycreate=false }},
[280] = { me_class_name = "Traffic descriptor",
	{ attname="CIR", length=4, setbycreate=true },
	{ attname="PIR", length=4, setbycreate=true },
	{ attname="CBS", length=4, setbycreate=true },
	{ attname="PBS", length=4, setbycreate=true },
	{ attname="Colour mode", length=1, setbycreate=true },
	{ attname="Ingress colour marking", length=1, setbycreate=true },
	{ attname="Egress colour marking", length=1, setbycreate=true },
	{ attname="Meter type", length=1, setbycreate=true }},
	

[281] = { me_class_name = "Multicast GEM interworking termination point",
	{ attname="GEM port network CTP connectivity pointer", length=2, setbycreate=true },
	{ attname="Interworking option", length=1, setbycreate=true },
	{ attname="Service profile pointer", length=2, setbycreate=true },
	{ attname="Interworking termination point pointer", length=2, setbycreate=true },
	{ attname="PPTP counter", length=1, setbycreate=false },
	{ attname="Operational state", length=1, setbycreate=false },
	{ attname="GAL profile pointer", length=2, setbycreate=true },
	{ attname="GAL loopback configuration", length=1, setbycreate=true },
	{ attname="Multicast address table", length=12, setbycreate=false }},

[287] = { me_class_name = "OMCI",
	{ attname="ME Type Table", length=2, setbycreate=false },
	{ attname="Message Type Table", length=2, setbycreate=false }},

[288] = { me_class_name = "Managed entity",
	{ attname="Name", length=25, setbycreate=false },
	{ attname="Attributes table", length=2, setbycreate=false },
	{ attname="Access", length=1, setbycreate=false },
	{ attname="Alarms table", length=1, setbycreate=false },
	{ attname="AVCs table", length=1, setbycreate=false },
	{ attname="Actions", length=4, setbycreate=false },
	{ attname="Instances table", length=2, setbycreate=false },
	{ attname="Support", length=1, setbycreate=false }},

[289] = { me_class_name = "Attribute",
	{ attname="Name", length=25, setbycreate=false },
	{ attname="Size", length=2, setbycreate=false },
	{ attname="Access", length=1, setbycreate=false },
	{ attname="Format", length=1, setbycreate=false },
	{ attname="Lower limit", length=4, setbycreate=false },
	{ attname="Upper limit", length=4, setbycreate=false },
	{ attname="Bit field", length=4, setbycreate=false },
	{ attname="Code points table", length=2, setbycreate=false },
	{ attname="Support", length=1, setbycreate=false }},

[290] = { me_class_name = "Dot1X Port Extension Package",
	{ attname="Dot1x Enable", length=1, setbycreate=false },
	{ attname="Action Register", length=1, setbycreate=false },
	{ attname="Authenticator PAE State", length=1, setbycreate=false },
	{ attname="Backend Authentication State", length=1, setbycreate=false },
	{ attname="Admin Controlled Directions", length=1, setbycreate=false },
	{ attname="Operational Controlled Directions", length=1, setbycreate=false },
	{ attname="Authenticator Controlled Port Status", length=1, setbycreate=false },
	{ attname="Quiet Period", length=2, setbycreate=false },
	{ attname="Server Timeout Period", length=2, setbycreate=false },
	{ attname="Reauthentication Period", length=2, setbycreate=false },
	{ attname="Reauthentication Enabled", length=1, setbycreate=false },
	{ attname="Key transmission Enabled", length=1, setbycreate=false }},
	
[291] = { me_class_name = "Dot1X configuration profile",
	{ attname="Circuit ID prefix", length=2, setbycreate=false },
	{ attname="Fallback policy", length=1, setbycreate=false },
	{ attname="Auth server 1", length=2, setbycreate=false },
	{ attname="Shared secret auth1", length=25, setbycreate=false },
	{ attname="Auth server 2", length=2, setbycreate=false },
	{ attname="Shared secret auth2", length=25, setbycreate=false },
	{ attname="Auth server 3", length=2, setbycreate=false },
	{ attname="Shared secret auth3", length=25, setbycreate=false },
	{ attname="OLT proxy address", length=4, setbycreate=false }},

[292] = { me_class_name = "Dot1X performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="EAPOL frames received", length=4, setbycreate=false },
	{ attname="EAPOL frames transmitted", length=4, setbycreate=false },
	{ attname="EAPOL start frames received", length=4, setbycreate=false },
	{ attname="EAPOL logoff frames received", length=4, setbycreate=false },
	{ attname="Invalid EAPOL frames received", length=4, setbycreate=false },
	{ attname="EAP resp/id frames received", length=4, setbycreate=false },
	{ attname="EAP response frames received", length=4, setbycreate=false },
	{ attname="EAP initial request frames transmitted", length=4, setbycreate=false },
	{ attname="EAP request frames transmitted", length=4, setbycreate=false },
	{ attname="EAP length error frames received", length=4, setbycreate=false },
	{ attname="EAP success frames generated autonomously", length=4, setbycreate=false },
	{ attname="EAP failure frames generated autonomously", length=4, setbycreate=false }},

[293] = { me_class_name = "Radius performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Access-request packets transmitted", length=4, setbycreate=false },
	{ attname="Access-request retransmission count", length=4, setbycreate=false },
	{ attname="Access-challenge packets received", length=4, setbycreate=false },
	{ attname="Access-accept packets received", length=4, setbycreate=false },
	{ attname="Access-reject packets received", length=4, setbycreate=false },
	{ attname="Invalid radius packets received", length=4, setbycreate=false }},

[296] = { me_class_name = "Ethernet PM History Data 3",
	{ attname="Interval End Time", length=1, setbycreate=false },
	{ attname="Threshold Data 1/2 Id", length=2, setbycreate=true },
	{ attname="Drop events", length=4, setbycreate=false },
	{ attname="Octets", length=4, setbycreate=false },
	{ attname="Packets", length=4, setbycreate=false },
	{ attname="Broadcast Packets", length=4, setbycreate=false },
	{ attname="Multicast Packets", length=4, setbycreate=false },
	{ attname="Undersize Packets", length=4, setbycreate=false },	
	{ attname="Fragments", length=4, setbycreate=false },	
	{ attname="Jabbers", length=4, setbycreate=false },	
	{ attname="Packets 64 Octets", length=4, setbycreate=false },
	{ attname="Packets 65 to 127 Octets", length=4, setbycreate=false },
	{ attname="Packets 128 to 255 Octets", length=4, setbycreate=false },
	{ attname="Packets 256 to 511 Octets", length=4, setbycreate=false },
	{ attname="Packets 512 to 1023 Octets", length=4, setbycreate=false },
	{ attname="Packets 1024 to 1518 Octets", length=4, setbycreate=false }},
	
[297] = { me_class_name = "Port mapping package",
	{ attname="Max ports", length=1, setbycreate=false },
	{ attname="Port list 1", length=16, setbycreate=false },
	{ attname="Port list 2", length=16, setbycreate=false },
	{ attname="Port list 3", length=16, setbycreate=false },
	{ attname="Port list 4", length=16, setbycreate=false },
	{ attname="Port list 5", length=16, setbycreate=false },
	{ attname="Port list 6", length=16, setbycreate=false },
	{ attname="Port list 7", length=16, setbycreate=false },
	{ attname="Port list 8", length=16, setbycreate=false }},
	
[298] = { me_class_name = "Dot1 rate limiter",
	{ attname="Parent ME pointer", length=2, setbycreate=true },
	{ attname="TP type", length=1, setbycreate=true },
	{ attname="Upstream unicast flood rate pointer", length=2, setbycreate=true },
	{ attname="Upstream broadcast rate pointer", length=2, setbycreate=true },
	{ attname="Upstream multicast payload rate pointer", length=2, setbycreate=true }},

[299] = { me_class_name = "Dot1ag maintenance domain",
	{ attname="MD level", length=1, setbycreate=true },
	{ attname="MD name format", length=1, setbycreate=true },
	{ attname="MD name 1, MD name 2", length=50, setbycreate=false },
	{ attname="MHF creation", length=1, setbycreate=true },
	{ attname="Sender ID permission", length=1, setbycreate=true }},

[300] = { me_class_name = "Dot1ag maintenance association",
	{ attname="MD pointer", length=2, setbycreate=true },
	{ attname="Short MA name format", length=1, setbycreate=true },
	{ attname="Short MA name 1, Short MA name 2", length=50, setbycreate=false },
	{ attname="CCM interval", length=1, setbycreate=true },
	{ attname="Associated VLANs", length=24, setbycreate=false },
	{ attname="MHF creation", length=1, setbycreate=true },
	{ attname="Sender ID permission", length=1, setbycreate=true }},
	
[301] = { me_class_name = "Dot1ag default MD level",
	{ attname="Layer 2 type", length=1, setbycreate=false },
	{ attname="Catchall level", length=1, setbycreate=false },
	{ attname="Catchall MHF creation", length=1, setbycreate=false },
	{ attname="Catchall sender ID permission", length=1, setbycreate=false },
	{ attname="Default MD level table", length=29, setbycreate=false }},
	
[302] = { me_class_name = "Dot1ag MEP",
	{ attname="Layer 2 entity pointer", length=2, setbycreate=true },
	{ attname="Layer 2 type", length=1, setbycreate=true },
	{ attname="MA pointer", length=2, setbycreate=true },
	{ attname="MEP ID", length=2, setbycreate=true },
	{ attname="MEP control", length=1, setbycreate=true },
	{ attname="Primary VLAN", length=2, setbycreate=true },
	{ attname="Administrative state", length=1, setbycreate=false },
	{ attname="CCM and LTM priority", length=1, setbycreate=true },
	{ attname="Egress identifier", length=8, setbycreate=true },
	{ attname="Peer MEP IDs", length=24, setbycreate=false },
	{ attname="ETH AIS control", length=1, setbycreate=true },
	{ attname="Fault alarm threshold", length=1, setbycreate=true },
	{ attname="Alarm declaration soak time", length=2, setbycreate=false },
	{ attname="Alarm clear soak time", length=2, setbycreate=false }},

[303] = { me_class_name = "Dot1ag MEP status",
	{ attname="MEP MAC address", length=6, setbycreate=false },
	{ attname="Fault notification generator state", length=1, setbycreate=false },
	{ attname="Highest priority defect observed", length=1, setbycreate=false },
	{ attname="Current defects", length=1, setbycreate=false },
	{ attname="Last received errored CCM table", length=128, setbycreate=false },
	{ attname="Last received xcon CCM table", length=128, setbycreate=false },
	{ attname="Out of sequence CCMs count", length=4, setbycreate=false },
	{ attname="CCMs transmitted count", length=4, setbycreate=false },
	{ attname="Unexpected LTRs count", length=4, setbycreate=false },
	{ attname="LBRs transmitted count", length=4, setbycreate=false },
	{ attname="Next loopback transaction identifier", length=4, setbycreate=false },
	{ attname="Next link trace transaction identifier", length=4, setbycreate=false }},

[304] = { me_class_name = "Dot1ag MEP CCM database",
	{ attname="RMEP 1 database table", length=N, setbycreate=false },
	{ attname="RMEP 2 database table", length=N, setbycreate=false },
	{ attname="RMEP 3 database table", length=N, setbycreate=false },
	{ attname="RMEP 4 database table", length=N, setbycreate=false },
	{ attname="RMEP 5 database table", length=N, setbycreate=false },
	{ attname="RMEP 6 database table", length=N, setbycreate=false },
	{ attname="RMEP 7 database table", length=N, setbycreate=false },
	{ attname="RMEP 8 database table", length=N, setbycreate=false },
	{ attname="RMEP 9 database table", length=N, setbycreate=false },
	{ attname="RMEP 10 database table", length=N, setbycreate=false },
	{ attname="RMEP 11 database table", length=N, setbycreate=false },
	{ attname="RMEP 12 database table", length=N, setbycreate=false }},

[305] = { me_class_name = "Dot1ag CFM stack",
	{ attname="Layer 2 type", length=1, setbycreate=false },
	{ attname="MP status table", length=18, setbycreate=false },
	{ attname="Configuration error list table", length=5, setbycreate=false }},

[306] = { me_class_name = "Dot1ag chassis-management info",
	{ attname="Chassis ID length", length=1, setbycreate=false },
	{ attname="Chassis ID subtype", length=1, setbycreate=false },
	{ attname="Chassis ID part 1, Chassis ID part 2", length=50, setbycreate=false },
	{ attname="Management address domain length", length=1, setbycreate=false },
	{ attname="Management address domain 1, Management address domain 2", length=50, setbycreate=false },
	{ attname="Management address length", length=1, setbycreate=false },
	{ attname="Management address 1, Management address 2", length=50, setbycreate=false }},

[307] = { me_class_name = "Octet string",
	{ attname="Length", length=2, setbycreate=false },
	{ attname="Part 1", length=25, setbycreate=false },
	{ attname="Part 2", length=25, setbycreate=false },
	{ attname="Part 3", length=25, setbycreate=false },
	{ attname="Part 4", length=25, setbycreate=false },
	{ attname="Part 5", length=25, setbycreate=false },
	{ attname="Part 6", length=25, setbycreate=false },
	{ attname="Part 7", length=25, setbycreate=false },
	{ attname="Part 8", length=25, setbycreate=false },
	{ attname="Part 9", length=25, setbycreate=false },
	{ attname="Part 10", length=25, setbycreate=false },
	{ attname="Part 11", length=25, setbycreate=false },
	{ attname="Part 12", length=25, setbycreate=false },
	{ attname="Part 13", length=25, setbycreate=false },
	{ attname="Part 14", length=25, setbycreate=false },
	{ attname="Part 15", length=25, setbycreate=false }},
	
[308] = { me_class_name = "General purpose buffer",
	{ attname="Maximum size", length=4, setbycreate=true },
	{ attname="Buffer table", length=1, setbycreate=false }},

[309] = { me_class_name = "Multicast operations profile",
	{ attname="IGMP version", length=1, setbycreate=true },
	{ attname="IGMP function", length=1, setbycreate=true },
	{ attname="Immediate leave", length=1, setbycreate=true },
	{ attname="Upstream IGMP TCI", length=2, setbycreate=true },
	{ attname="Upstream IGMP tag control", length=1, setbycreate=true },
	{ attname="Upstream IGMP rate", length=4, setbycreate=true },
	{ attname="Dynamic access control list table", length=24, setbycreate=false },
	{ attname="Static access control list table", length=24, setbycreate=false },	
	{ attname="Lost groups list table", length=10, setbycreate=false },		
	{ attname="Robustness", length=1, setbycreate=true },	
	{ attname="Querier IP address", length=4, setbycreate=true },		
	{ attname="Query interval", length=4, setbycreate=true },		
	{ attname="Query max response time", length=4, setbycreate=true },		
	{ attname="Last member query interval", length=4, setbycreate=false },		
	{ attname="Unauthorized join request behaviour", length=1, setbycreate=false },		
	{ attname="Downstream IGMP and multicast TCI", length=3, setbycreate=true }},

[310] = { me_class_name = "Multicast subscriber config info",
	{ attname="ME type", length=1, setbycreate=true },
	{ attname="Multicast operations profile pointer", length=2, setbycreate=true },
	{ attname="Max simultaneous groups", length=2, setbycreate=true },
	{ attname="Max multicast bandwidth", length=4, setbycreate=true },
	{ attname="Bandwidth enforcement", length=1, setbycreate=true },
	{ attname="Multicast service package table", length=20, setbycreate=false },
	{ attname="Allowed preview groups table", length=22, setbycreate=false }},	
	
[311] = { me_class_name = "Multicast Subscriber Monitor",
	{ attname="ME type", length=1, setbycreate=true },
	{ attname="Current multicast bandwidth", length=4, setbycreate=false },
	{ attname="Max Join messages counter", length=4, setbycreate=false },
	{ attname="Bandwidth exceeded counter:", length=4, setbycreate=false },
	{ attname="Active group list table", length=24, setbycreate=false }},	

[312] = { me_class_name = "FEC PM History Data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Corrected bytes", length=4, setbycreate=false },
	{ attname="Corrected code words", length=4, setbycreate=false },
	{ attname="Uncorrectable code words", length=4, setbycreate=false },
	{ attname="Total code words", length=4, setbycreate=false },
	{ attname="FEC seconds", length=2, setbycreate=false }},

[318] = { me_class_name = "File transfer controller",
	{ attname="Supported transfer protocols", length=2, setbycreate=false },
	{ attname="File type", length=2, setbycreate=false },
	{ attname="File instance", length=2, setbycreate=false },
	{ attname="Local file name pointer", length=2, setbycreate=false },
	{ attname="Network address pointer", length=2, setbycreate=false },
	{ attname="File transfer trigger", length=1, setbycreate=false },
	{ attname="File transfer status", length=1, setbycreate=false },
	{ attname="GEM IWTP pointer", length=2, setbycreate=false },
	{ attname="VLAN", length=2, setbycreate=false },
	{ attname="File size", length=4, setbycreate=false },
	{ attname="Directory listing table", length=1, setbycreate=false }},

[321] = { me_class_name = "Ethernet Frame PM History Data DS",
	{ attname="Interval End Time", length=1, setbycreate=false },
	{ attname="Threshold Data 1/2 Id", length=2, setbycreate=true },
	{ attname="Drop events", length=4, setbycreate=false },
	{ attname="Octets", length=4, setbycreate=false },
	{ attname="Packets", length=4, setbycreate=false },
	{ attname="Broadcast Packets", length=4, setbycreate=false },
	{ attname="Multicast Packets", length=4, setbycreate=false },
	{ attname="CRC Errored Packets", length=4, setbycreate=false },	
	{ attname="Undersize Packets", length=4, setbycreate=false },	
	{ attname="Oversize Packets", length=4, setbycreate=false },
	{ attname="Packets 64 Octets", length=4, setbycreate=false },
	{ attname="Packets 65 to 127 Octets", length=4, setbycreate=false },
	{ attname="Packets 128 to 255 Octets", length=4, setbycreate=false },
	{ attname="Packets 256 to 511 Octets", length=4, setbycreate=false },
	{ attname="Packets 512 to 1023 Octets", length=4, setbycreate=false },
	{ attname="Packets 1024 to 1518 Octets", length=4, setbycreate=false }},

[322] = { me_class_name = "Ethernet Frame PM History Data US",
	{ attname="Interval End Time", length=1, setbycreate=false },
	{ attname="Threshold Data 1/2 Id", length=2, setbycreate=true },
	{ attname="Drop events", length=4, setbycreate=false },
	{ attname="Octets", length=4, setbycreate=false },
	{ attname="Packets", length=4, setbycreate=false },
	{ attname="Broadcast Packets", length=4, setbycreate=false },
	{ attname="Multicast Packets", length=4, setbycreate=false },
	{ attname="CRC Errored Packets", length=4, setbycreate=false },	
	{ attname="Undersize Packets", length=4, setbycreate=false },	
	{ attname="Oversize Packets", length=4, setbycreate=false },
	{ attname="Packets 64 Octets", length=4, setbycreate=false },
	{ attname="Packets 65 to 127 Octets", length=4, setbycreate=false },
	{ attname="Packets 128 to 255 Octets", length=4, setbycreate=false },
	{ attname="Packets 256 to 511 Octets", length=4, setbycreate=false },
	{ attname="Packets 512 to 1023 Octets", length=4, setbycreate=false },
	{ attname="Packets 1024 to 1518 Octets", length=4, setbycreate=false }},

[329] = { me_class_name = "Virtual Ethernet interface point",
	{ attname="Administrative state", length=1, setbycreate=false },
	{ attname="Operational state", length=1, setbycreate=false },
	{ attname="Interdomain name", length=25, setbycreate=false },
	{ attname="TCP/UDP pointer", length=2, setbycreate=false },
	{ attname="IANA assigned port", length=2, setbycreate=false }},

[330] = { me_class_name = "Generic status portal",
	{ attname="Status document table", length=1, setbycreate=false },
	{ attname="Configuration document table", length=1, setbycreate=false },
	{ attname="AVC report rate", length=1, setbycreate=true }},
	
[331] = { me_class_name = "ONU-E",
	{ attname="Vendor id", length=4, setbycreate=false },
	{ attname="Version", length=14, setbycreate=false },
	{ attname="Serial number", length=8, setbycreate=false }},
	
[332] = { me_class_name = "Enhanced security control ",
	{ attname="OLT crypto capabilities", length=16, setbycreate=false },
	{ attname="OLT random challenge table", length=17, setbycreate=false },
	{ attname="OLT challenge status", length=1, setbycreate=false },
	{ attname="ONU  selected  crypto  capabilities", length=1, setbycreate=false },
	{ attname="ONU random challenge table", length=16, setbycreate=false },
	{ attname="ONU authentication result table", length=16, setbycreate=false },
	{ attname="OLT authentication result table", length=17, setbycreate=false },
	{ attname="OLT result status", length=1, setbycreate=false },
	{ attname="ONU  authentication  status", length=1, setbycreate=false },
	{ attname="Master  session  key  name", length=16, setbycreate=false },
	{ attname="Broadcast key table", length=18, setbycreate=false },
	{ attname="Effective key length", length=2, setbycreate=false }},
	
[334] = { me_class_name = "Ethernet frame extended PM",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Control Block", length=16, setbycreate=true },
	{ attname="Drop events", length=4, setbycreate=false },
	{ attname="Octets", length=4, setbycreate=false },
	{ attname="Frames", length=4, setbycreate=false },
	{ attname="Broadcast frames", length=4, setbycreate=false },
	{ attname="Multicast frames", length=4, setbycreate=false },
	{ attname="CRC errored frames", length=4, setbycreate=false },
	{ attname="Undersize frames", length=4, setbycreate=false },
	{ attname="Oversize frames", length=4, setbycreate=false },
	{ attname="Frames 64 octets", length=4, setbycreate=false },
	{ attname="Frames 65 to 127 octets", length=4, setbycreate=false },
	{ attname="Frames 128 to 255 octets", length=4, setbycreate=false },
	{ attname="Frames 256 to 511 octets", length=4, setbycreate=false },
	{ attname="Frames 512 to 1023 octets", length=4, setbycreate=false },
	{ attname="Frames 1024 to 1518 octets", length=4, setbycreate=false }},

[335] = { me_class_name = "SNMP configuration data",
	{ attname="SNMP version", length=2, setbycreate=true },
	{ attname="SNMP agent address", length=2, setbycreate=true },
	{ attname="SNMP server address", length=4, setbycreate=true },
	{ attname="SNMP server port", length=2, setbycreate=true },
	{ attname="Security name pointer", length=2, setbycreate=true },
	{ attname="Community for read", length=2, setbycreate=true },
	{ attname="Community for write", length=2, setbycreate=true },
	{ attname="Sys name pointer", length=2, setbycreate=true }},

[336] = { me_class_name = "ONU dynamic power management control",
	{ attname="Power reduction management capability", length=1, setbycreate=false },
	{ attname="Power reduction management mode", length=1, setbycreate=false },
	{ attname="Itransinitr", length=2, setbycreate=false },
	{ attname="Itxinit", length=2, setbycreate=false },
	{ attname="Maximum sleep interval", length=4, setbycreate=false },
	{ attname="Minimum aware interval", length=4, setbycreate=false },
	{ attname="Minimum active held interval", length=2, setbycreate=false }},

[340] = { me_class_name = "TR-069 management server",
	{ attname="Administrative state", length=1, setbycreate=false },
	{ attname="ACS network address", length=2, setbycreate=false },
	{ attname="Associated tag", length=2, setbycreate=false }},

[341] = { me_class_name = "GEM port network CTP performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Transmitted GEM frames", length=4, setbycreate=false },
	{ attname="Received GEM frames", length=4, setbycreate=false },
	{ attname="Received payload bytes", length=8, setbycreate=false },
	{ attname="Transmitted payload bytes", length=8, setbycreate=false },
	{ attname="Encryption key errors", length=4, setbycreate=false }},
	
[342] = { me_class_name = "TCP/UDP performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Socket failed", length=2, setbycreate=false },
	{ attname="Listen failed", length=2, setbycreate=false },
	{ attname="Bind failed", length=2, setbycreate=false },
	{ attname="Accept failed", length=2, setbycreate=false },
	{ attname="Select failed", length=2, setbycreate=false }},


[342] = { me_class_name = "TCP/UDP performance monitoring history data",
	{ attname="Interval end time", length=1, setbycreate=false },
	{ attname="Threshold data 1/2 id", length=2, setbycreate=true },
	{ attname="Socket failed", length=2, setbycreate=false },
	{ attname="Listen failed", length=2, setbycreate=false },
	{ attname="Bind failed", length=2, setbycreate=false },
	{ attname="Accept failed", length=2, setbycreate=false },
	{ attname="Select failed", length=2, setbycreate=false }},
	
[349] = { me_class_name = "Power Over Ethernet Control",
    { attname = "PoE capabilities", length = 2, setbycreate = true },
    { attname = "Power pair pinout control", length = 1, setbycreate = true },
    { attname = "Operational state", length = 1, setbycreate = false },
    { attname = "Power detection status", length = 1, setbycreate = false },
    { attname = "Power classification status", length = 1, setbycreate = false },
    { attname = "Power priority", length = 1, setbycreate = true },
    { attname = "Invalid signature counter", length = 2, setbycreate = false },
    { attname = "Power denied counter", length = 2, setbycreate = false },
    { attname = "Overload counter", length = 2, setbycreate = false },
    { attname = "Short counter", length = 2, setbycreate = false },
    { attname = "MPS absent counter", length = 2, setbycreate = false },
    { attname = "PSE class control", length = 1, setbycreate = true },
    { attname = "Current power consumption", length = 4, setbycreate = false }},
	
[425] = { me_class_name = "Ethernet Frame extend PM 64 bit",
	{ attname="Interval End Time", length=1, setbycreate=false },
	{ attname="Control block", length=16, setbycreate=true },
	{ attname="Drop events", length=8, setbycreate=false },
	{ attname="Octets", length=8, setbycreate=false },
	{ attname="Packets", length=8, setbycreate=false },
	{ attname="Broadcast Packets", length=8, setbycreate=false },
	{ attname="Multicast Packets", length=8, setbycreate=false },
	{ attname="CRC errored Packets", length=8, setbycreate=false },
	{ attname="Undersize Packets", length=8, setbycreate=false },		
	{ attname="oversize Packets", length=8, setbycreate=false },	
	{ attname="Packets 64 Octets", length=8, setbycreate=false },
	{ attname="Packets 65 to 127 Octets", length=8, setbycreate=false },
	{ attname="Packets 128 to 255 Octets", length=8, setbycreate=false },
	{ attname="Packets 256 to 511 Octets", length=8, setbycreate=false },
	{ attname="Packets 512 to 1023 Octets", length=8, setbycreate=false },
	{ attname="Packets 1024 to 1518 Octets", length=8, setbycreate=false }},	

[65528] = { me_class_name = "ONU Loop Detect",
	{ attname="Operator ID", length=4, setbycreate=false },
	{ attname="Loop Detection Management", length=2, setbycreate=false },
	{ attname="Looped Port Down", length=2, setbycreate=false },
	{ attname="Loop Detect Message Frequency", length=2, setbycreate=false },
	{ attname="Loop Receive Interval", length=2, setbycreate=false },
	{ attname="Port And VLAN Table", length=7, setbycreate=false }},
[65529] = { me_class_name = "ONU capability",
	{ attname="Operator ID", length=4, setbycreate=false },
	{ attname="CTC Spec Version", length=1, setbycreate=false },
	{ attname="ONU type", length=1, setbycreate=false },
	{ attname="ONU Tx power supply control", length=1, setbycreate=false }},
	
[65530] = { me_class_name = "LOID authentication",
	{ attname="Operator ID", length=4, setbycreate=false },
	{ attname="LOID", length=12, setbycreate=false },
	{ attname="Password", length=12, setbycreate=false },
	{ attname="Authentication status", length=1, setbycreate=false }},
	
[65531] = { me_class_name = "Extended multicast operations profiles",
	{ attname="IGMP version", length=1, setbycreate=true },
	{ attname="IGMP function", length=1, setbycreate=true },
	{ attname="Immediate leave", length=1, setbycreate=true },
	{ attname="Upstream IGMP TCI", length=2, setbycreate=true },
	{ attname="Upstream IGMP tag control", length=1, setbycreate=true },
	{ attname="Upstream IGMP rate", length=4, setbycreate=true },
	{ attname="Dynamic access control list table", length=30, setbycreate=false },
	{ attname="Static access control list table", length=30, setbycreate=false },
	{ attname="Lost groups list table", length=16, setbycreate=false },
	{ attname="Robustness", length=1, setbycreate=true },
	{ attname="Querier IP address", length=16, setbycreate=false },
	{ attname="Query interval", length=4, setbycreate=true },
	{ attname="Query max response time", length=4, setbycreate=true },
	{ attname="Last member query interval", length=4, setbycreate=false },
	{ attname="Unauthorized join request behaviour", length=1, setbycreate=false },
	{ attname="Downstream IGMP and multicast TCI", length=3, setbycreate=true }},
			
}

setmetatable(omci_def, mt2)

-- GUI field definition
local f = omciproto.fields
f.tci = ProtoField.uint16("omciproto.tci", "Transaction Correlation ID", base.HEX)
f.msg_type_db = ProtoField.uint8("omciproto.msg_type_db", "Destination Bit", base.HEX, nil, 0x80)
f.msg_type_ar = ProtoField.uint8("omciproto.msg_type_ar", "Acknowledge Request", base.HEX, nil, 0x40)
f.msg_type_ak = ProtoField.uint8("omciproto.msg_type_ak", "Acknowledgement", base.HEX, nil, 0x20)
f.msg_type_mt = ProtoField.uint8("omciproto.msg_type_mt", "Message Type", base.DEC, msgtype, 0x1F)
f.dev_id = ProtoField.uint8("omciproto.dev_id", "Device Identifier", base.HEX)
f.me_id = ProtoField.uint16("omciproto.me_id", "Managed Entity Instance", base.HEX)
f.me_class = ProtoField.uint16("omciproto.me_class", "Managed Entity Class", base.DEC) 
f.me_class_str = ProtoField.string("omciproto.me_class_str", "Managed Entity Class") 
f.extend_omci_msgContLen = ProtoField.uint16("omciproto.extend_omci_msgContLen", "Message Content Lenth HEX", base.HEX) 
f.attribute_mask = ProtoField.uint16("omciproto.attribtute_mask", "Attribute Mask", base.HEX, nil, 0xFFFF)
f.attribute = ProtoField.bytes("omciproto.attribute", "Attribute")
f.content = ProtoField.bytes("omciproto.content", "Message Content")
f.trailer = ProtoField.bytes("omciproto.trailer", "Trailer")
f.cpcsuu_cpi = ProtoField.uint16("omciproto.cpcsuu_cpi", "CPCS-UU and CPI", base.HEX)
f.cpcssdu_length = ProtoField.uint16("omciproto.cpcssdu_length", "CPCS-SDU Length", base.HEX)
f.crc32 = ProtoField.uint32("omciproto.crc32", "CRC32", base.HEX)
f.oltAllAlarm0 = ProtoField.uint8("omciproto.oltAllAlarm", " Get all alarms regardless of ARC status", base.HEX, nil, 0x01)
f.oltAllAlarm1 = ProtoField.uint8("omciproto.oltAllAlarm", " Get all alarms not currently under ARC", base.HEX, nil, 0x01)



local ext_vlan_op_tbl ={
	{attrname = "Filter outer priority", len  = 4 },
	{attrname = "Filter outer VID", len  = 13 },
	{attrname = "Filter outer VID", len  = 3 },
	{attrname = "reserved", len  = 12 },
	{attrname = "Filter inner priority", len  = 4},
	{attrname = "Filter inner VID", len  = 13 },
	{attrname = "Filter inner TPID/DEI", len  = 3 },
	{attrname = "reserved", len  = 8 },
	{attrname = "Filter  Ethertype", len  = 4},
	{attrname = "Treatment tags to remove", len  = 2 },
	{attrname = "reserved", len  = 10 },
	{attrname = "Treatment outer priority", len  = 4 },
	{attrname = "Treatment outer VID", len  = 13 },
	{attrname = "Treatment outer TPID/DEI", len  = 3 },
	{attrname = "reserved", len  = 12 },
	{attrname = "Treatment inner priority", len  = 4 },
	{attrname = "Treatment inner VID", len  = 13 },
	{attrname = "Treatment inner TPID/DEI", len  = 3 },
} 


-- The dissector function
function omciproto.dissector (buffer, pinfo, tree)
	if buffer:len() == 0 then return end -- validate packet length is adequate, otherwise quit

	-- Extract timestamp info from DST/SRC MAC
	local eth_dst = tostring(pinfo.dst)
    	local eth_src = tostring(pinfo.src)

	--some MAC foramt is XX:XX:XX_XX:XX:XX, repace "_" to ":"
	eth_dst = string.gsub(eth_dst , "_", ":")
	eth_src = string.gsub(eth_src , "_", ":")
	

    	local year1, year2, month, day, hour, minute  = string.match(eth_dst , "(%d+):(%d+):(%d+):(%d+):(%d+):(%d+)")
    	local sec, mmsec1, mmsec2, usec1, usec2 = string.match(eth_src , "(%d+):(%d+):(%d+):(%d+):(%d+)")


    	local ts = tostring(pinfo.abs_ts)
    	local startIndex, endIndex = ts:find("%.%d+")
    	local usec = ts:sub(startIndex + 1, endIndex)
    
    	local timestamp_date = string.format("%s%s.%s.%s-%s:%s:%s.%s", year1, year2, month, day, hour, minute, sec, usec)

	-- Show name of the protocol, create Tree item for displaying info
	pinfo.cols.protocol = omciproto.name
	local subtree = tree:add(omciproto, buffer())

	-- Start analysing data
	local offset = 0
	
	-- OMCI Transaction Correlation Identifier
	local tci = buffer(offset, 2)
	subtree:add(f.tci, tci)
	offset = offset +  2
	
	-- OMCI Message Type
	local msg_type = buffer(offset, 1)
	local msg_type_mt = msgtype[msg_type:bitfield(3,5)]
	local msg_type_ar = msg_type:bitfield(1,1)
	local msg_type_ak = msg_type:bitfield(2,1)
	local msgtype_subtree = subtree:add(msg_type, "Message Type = " .. msg_type_mt)
	msgtype_subtree:add(f.msg_type_db, msg_type)
	msgtype_subtree:add(f.msg_type_ar, msg_type)
	msgtype_subtree:add(f.msg_type_ak, msg_type)
	msgtype_subtree:add(f.msg_type_mt, msg_type)
	offset = offset +  1
	
	-- OMCI Device ID
	local dev_id = buffer(offset, 1)
	subtree:add(f.dev_id, dev_id)
	offset = offset +  1
	
	-- OMCI Message Entity Class & Instance
	local me_class = buffer(offset, 2)
	local me_instance = buffer(offset + 2, 2)
	local me_class_name = omci_def[me_class:uint()].me_class_name
	
	local devid_subtree = subtree:add(buffer(offset, 4), "Message Identifier, ME Class = " .. me_class_name .. ", Instance = " .. me_instance:uint())
--	devid_subtree:add(f.me_class, me_class)
	devid_subtree:add(me_class, "Managed Entity Class: " .. me_class_name .. " (" .. tostring(BinDecHex.Hex2Dec(tostring(me_class))) ..--[[.. me_class .. --]]")")
	devid_subtree:add(f.me_id, me_instance)
	offset = offset +  4
	--print(dev_id)
	local content
	--debug(dev_id)
	local msgLen
	if(dev_id:uint() == 0x0b) then
		msgLen = buffer(offset, 2)
		local ext_omci=subtree:add(buffer(offset, 2), "Extend OMCI Messge Content Length = " ..msgLen:uint())
		ext_omci:add(f.extend_omci_msgContLen, msgLen)
		offset = offset +  2
		content = buffer(offset, msgLen:uint())
	else
		content = buffer(offset, 32)
	end
	
	-- OMCI Attributes and/or message result	
	--local content = buffer(offset, 32)
	if( (msg_type_mt == "Get" or msg_type_mt == "Get Current Data") and msg_type_ar == 1 and msg_type_ak == 0) then
		local attribute_mask = content(0, 2)
		local attributemask_subtree = subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
		attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
		local content_subtree = subtree:add(content, "Attribute List")
		attributes = omci_def[me_class:uint()]
		for i = 1,#attributes do
			local attr = attributes[i]
			if attribute_mask:bitfield(i-1,1) == 1 then
				content_subtree:add(string.format("%2.2d", i) .. ": " .. attr.attname)
			end
		end
	end
    

	if( (msg_type_mt == "Get" or msg_type_mt == "Get Current Data") and msg_type_ar == 0 and msg_type_ak == 1) then
		result_code = content(0,1):uint()
		subtree:add(content(0,1), "Result: " .. msg_result[content(0,1):uint()] .. " (" .. content(0,1) .. ")")
		if(dev_id:uint() == 0x0b) then
			local attribute_mask
			local attributemask_subtree
			if(msgLen:uint() >= 7) then
				attribute_mask = content(1, 2)
				local optionmask_subtree = subtree:add(content(3, 2), "Optional-Attribute Mask (0x" .. content(3, 2) .. ")" )
				optionmask_subtree:add(content(3, 2), tostring(BinDecHex.Hex2Bin(tostring(content(3, 2)))))
				local exemask_subtree = subtree:add(content(5, 2), "Attribute Execution Mask (0x" .. content(5, 2) .. ")" )
				exemask_subtree:add(content(5, 2), tostring(BinDecHex.Hex2Bin(tostring(content(5, 2)))))
				attributemask_subtree = subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
				attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
				
			end
			if(msgLen:uint() > 7) then
				local content_subtree = subtree:add(content(7,msgLen:uint()-7), "Attribute List")
				local attributes = {}
				local attribute_offset = 0
				attributes = omci_def[me_class:uint()]
				attribute_offset=7
				for i = 1,#attributes do
					local attr = attributes[i]
					if attribute_mask:bitfield(i-1,1) == 1 then
						local attr_bytes = content(attribute_offset, attr.length)
						content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
						attribute_offset = attribute_offset + attr.length
					end
				end
			end
		else
			local attribute_mask = content(1, 2)
			local attributemask_subtree = subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
			attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
			local content_subtree = subtree:add(content(3,25), "Attribute List")
			local attributes = {}
			local attribute_offset = 0
			attributes = omci_def[me_class:uint()]
			attribute_offset=3
			for i = 1,#attributes do
				local attr = attributes[i]
				if attribute_mask:bitfield(i-1,1) == 1 then
					local attr_bytes = content(attribute_offset, attr.length)
					content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
					attribute_offset = attribute_offset + attr.length
				end
			end
			local optionmask_subtree = subtree:add(content(28, 2), "Optional-Attribute Mask (0x" .. content(28, 2) .. ")" )
			optionmask_subtree:add(content(28, 2), tostring(BinDecHex.Hex2Bin(tostring(content(28, 2)))))
			local exemask_subtree = subtree:add(content(30, 2), "Attribute Execution Mask (0x" .. content(30, 2) .. ")" )
			exemask_subtree:add(content(30, 2), tostring(BinDecHex.Hex2Bin(tostring(content(30, 2)))))
				
		end
	end

	if( msg_type_mt == "Set" and msg_type_ar == 1 and msg_type_ak == 0 and me_class:uint() ~= 171 ) then
		local attribute_mask = content(0, 2)
		local attributemask_subtree = subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
		attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
		local content_subtree 
		if(dev_id:uint() == 0x0a) then
			content_subtree = subtree:add(content(2,30), "Attribute List")
		else
			content_subtree = subtree:add(content(2,msgLen:uint()-2), "Attribute List")
		end
		local attributes = {}
		local attribute_offset = 0
		attributes = omci_def[me_class:uint()]
		attribute_offset=2
		for i = 1,#attributes do
			local attr = attributes[i]
			if attribute_mask:bitfield(i-1,1) == 1 then
				local attr_bytes = content(attribute_offset, attr.length)
				content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
				attribute_offset = attribute_offset + attr.length
			end
		end
	end

	-- for set Extended Vlan Operation ME
	if( msg_type_mt == "Set" and msg_type_ar == 1 and msg_type_ak == 0 and me_class:uint() == 171 ) then
		local attribute_mask = content(0, 2)
		local attributemask_subtree = subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
		attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
		local content_subtree
		if(dev_id:uint() == 0x0a) then
			content_subtree = subtree:add(content(2,30), "Attribute List")
		else
			content_subtree = subtree:add(content(2,msgLen:uint()-2), "Attribute List")
		end
		local attributes = {}
		local attribute_offset = 0
		attributes = omci_def[me_class:uint()]
		attribute_offset=2
		for i = 1,#attributes do
			local attr = attributes[i]
			if attribute_mask:bitfield(i-1,1) == 1 then
				local attr_bytes = content(attribute_offset, attr.length)
				local bits_detail_subtree = content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
				attribute_offset = attribute_offset + attr.length
				if  i == 6 then
					local start_pos = 0;
					for j = 1, #ext_vlan_op_tbl do
						local bit_attr_desc = ext_vlan_op_tbl[j]
						local bit_attr_val = attr_bytes:bitfield(start_pos, bit_attr_desc.len)
						start_pos = start_pos + bit_attr_desc.len;
						bits_detail_subtree:add( bit_attr_desc.attrname .. ": " .. bit_attr_val)
					end
				end
			end
		end
	end
	if( msg_type_mt == "Set Table" and msg_type_ar == 1 and msg_type_ak == 0) then
		local attribute_mask = content(0, 2)
		local attributemask_subtree = subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
		attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
		local content_subtree = subtree:add(content(2,msgLen:uint()-2), "Attribute List")
		local Entry_offset = 2
		local EntryIndex = 1
		local attributes = {}
		attributes = omci_def[me_class:uint()]
		while(Entry_offset < msgLen:uint())
		do
			for i = 1,#attributes do
				local attr = attributes[i]
				if attribute_mask:bitfield(i-1,1) == 1 then
					local attr_bytes = content(Entry_offset, attr.length)
					local tableEntry_subtree=content_subtree:add(attr_bytes, "Entry(" .. EntryIndex .. "): " .. attr_bytes)
					local bits_detail_subtree = tableEntry_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
					Entry_offset = Entry_offset + attr.length
					EntryIndex = EntryIndex + 1
					if  (me_class:uint() == 171 and i == 6) then
						local start_pos = 0;
						for j = 1, #ext_vlan_op_tbl do
							local bit_attr_desc = ext_vlan_op_tbl[j]
							local bit_attr_val = attr_bytes:bitfield(start_pos, bit_attr_desc.len)
							start_pos = start_pos + bit_attr_desc.len;
							bits_detail_subtree:add( bit_attr_desc.attrname .. ": " .. bit_attr_val)
						end
					end
				end
			end
		end		
	end
	
	if( (msg_type_mt == "MIB Reset" or msg_type_mt == "Test"
			or msg_type_mt == "Activate Software" or msg_type_mt == "Commit Software"
			or msg_type_mt == "Reboot" or msg_type_mt == "Delete" or msg_type_mt =="Set Table") 
		and msg_type_ar == 0 and msg_type_ak == 1) then
		result_code = content(0,1):uint()
		subtree:add(content(0,1), "Result: " .. msg_result[content(0,1):uint()] .. " (" .. content(0,1) .. ")")
	end
	
	if(msg_type_mt == "Create"  and msg_type_ar == 0 and msg_type_ak == 1) then
		result_code = content(0,1):uint()
		subtree:add(content(0,1), "Result: " .. msg_result[content(0,1):uint()] .. " (" .. content(0,1) .. ")")
		if((dev_id:uint() == 0x0b and msgLen:uint() > 1) or dev_id:uint() == 0x0a) then
			subtree:add(content(1,2), "Attribute Execute Mask: 0x" .. content(1,2))
		end
	end
	if(msg_type_mt == "Set"  and msg_type_ar == 0 and msg_type_ak == 1) then
		result_code = content(0,1):uint()
		subtree:add(content(0,1), "Result: " .. msg_result[content(0,1):uint()] .. " (" .. content(0,1) .. ")")
		if((dev_id:uint() == 0x0b and msgLen:uint() > 1) or dev_id:uint() == 0x0a) then
			subtree:add(content(1,2), "Optional Attribute Mask: 0x" .. content(1,2))
		end
		if((dev_id:uint() == 0x0b and msgLen:uint() > 3) or dev_id:uint() == 0x0a) then
			subtree:add(content(3,2), "Attribute Execute Mask: 0x" .. content(3,2))
		end
	end

	if( msg_type_mt == "Create" and msg_type_ar == 1 and msg_type_ak == 0) then
		local content_subtree = subtree:add(content, "Attribute List")
		local attributes = {}
		local attribute_offset = 0
		attributes = omci_def[me_class:uint()]
		attribute_offset=0
		local allAttrLen=0
		for i = 1,#attributes do
			local attr = attributes[i]
			if attr.setbycreate then
				allAttrLen = allAttrLen + attr.length
				if((dev_id:uint() == 0x0b and allAttrLen <= msgLen:uint()) or dev_id:uint() == 0x0a) then
					local attr_bytes = content(attribute_offset, attr.length)
					content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
					attribute_offset = attribute_offset + attr.length
				end
			end
		end
	end

	if(msg_type_mt == "MIB Upload" and msg_type_ar == 0 and msg_type_ak == 1) then
		subtree:add(content(0,2), "Number of subsequent commands: " .. content(0,2):uint() .. " (" .. content(0,2) .. ")")
	end

	if(msg_type_mt == "MIB Upload Next" and msg_type_ar == 1 and msg_type_ak == 0) then
		subtree:add(content(0,2), "Command number: " .. content(0,2):uint() .. " (" .. content(0,2) .. ")")
	end

	if(msg_type_mt == "MIB Upload Next" and msg_type_ar == 0 and msg_type_ak == 1) then
		local upload_substree = subtree:add(content, "ME Class Upload Content")
		if(dev_id:uint() == 0x0b) then
			local MibmsgLen=0
			local upload_me_class 
			local inst_subtree
			while(MibmsgLen < msgLen:uint())
			do
				local instContLen = content(0+MibmsgLen,2)
				upload_me_class = content(2+MibmsgLen,2)
				inst_subtree = upload_substree:add( instContLen, "ME Class = " .. omci_def[upload_me_class:uint()].me_class_name .. ", Intance = 0x" .. content(4+MibmsgLen,2) .. ", Content Length: " .. instContLen:uint())
				
				--debug("instConten Len: " .. instContLen:uint())
				upload_me_class = content(2+MibmsgLen,2)
				inst_subtree:add( upload_me_class, "Managed Entity Class: " .. omci_def[upload_me_class:uint()].me_class_name .. " (" .. upload_me_class:uint() .. ")")
				inst_subtree:add(content(4+MibmsgLen,2), "Managed Entity Instance: " .. content(4+MibmsgLen,2):uint() .. " (0x" .. content(4+MibmsgLen,2) .. ")")
				local attribute_mask = content(6+MibmsgLen, 2)
				local attributemask_subtree = inst_subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
				attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
				local content_subtree = inst_subtree:add(content(8+MibmsgLen,instContLen:uint()), "Attribute List")
				local attributes = {}
				local attribute_offset
				attributes = omci_def[upload_me_class:uint()]
				attribute_offset=8+MibmsgLen
				for i = 1,#attributes do
					local attr = attributes[i]
					if attribute_mask:bitfield(i-1,1) == 1 then
						local attr_bytes = content(attribute_offset, attr.length)
						content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
						attribute_offset = attribute_offset + attr.length
					end			
				end
				MibmsgLen = MibmsgLen + instContLen:uint()+8
				--debug("current Len: " .. MibmsgLen)
				--debug("total len: " .. msgLen:uint())
			end
			me_class_name = me_class_name .. " (" .. omci_def[upload_me_class:uint()].me_class_name .. ")"
		else
			local upload_me_class = content(0,2)
			upload_substree:add( upload_me_class, "Managed Entity Class: " .. omci_def[upload_me_class:uint()].me_class_name .. " (" .. upload_me_class:uint() .. ")")
			upload_substree:add(content(2,2), "Managed Entity Instance: " .. content(2,2):uint() .. " (0x" .. content(2,2) .. ")")
			local attribute_mask = content(4, 2)
			local attributemask_subtree = upload_substree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
			attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
			local content_subtree = upload_substree:add(content, "Attribute List")
			local attributes = {}
			local attribute_offset
			attributes = omci_def[upload_me_class:uint()]
			attribute_offset=6
			for i = 1,#attributes do
				local attr = attributes[i]
				if attribute_mask:bitfield(i-1,1) == 1 then
					local attr_bytes = content(attribute_offset, attr.length)
					content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
					attribute_offset = attribute_offset + attr.length
				end			
			end
			me_class_name = me_class_name .. " (" .. omci_def[upload_me_class:uint()].me_class_name .. ")"
		end
	end
	
	if(msg_type_mt == "Get All Alarms" and msg_type_ar == 1 and msg_type_ak == 0) then
		local allAlarmContent= subtree:add(content(0,1), "alarm retrieval mode: 0x" .. content(0,1))
		local avcVal=content(0,1):bitfield(1,1)
		if(avcVal) then
			allAlarmContent:add(f.oltAllAlarm1, avcVal)
		else
			allAlarmContent:add(f.oltAllAlarm0, avcVal)
		end
	end
	
	if(msg_type_mt == "Get All Alarms" and msg_type_ar == 0 and msg_type_ak == 1) then
		if(dev_id:uint() == 0x0b) then
			subtree:add(content(0,2), "Number of ME instances to be retrieved: " .. content(0,2):uint())
		else
			subtree:add(content(0,2), "Number of subsequent get all alarms next commands : " .. content(0,2):uint())
		end
	end
	
	if(msg_type_mt == "Get All Alarms Next" and msg_type_ar == 1 and msg_type_ak == 0) then
		subtree:add(content(0,2), "Command sequence number: 0x" .. content(0,2))
	end
	
	if(msg_type_mt == "Get All Alarms Next" and msg_type_ar == 0 and msg_type_ak == 1) then
		if(dev_id:uint() == 0x0b) then
			local alarmNext_len = msgLen:uint()
			local content_pos = 0
			local alarmNext_substree
			if(alarmNext_len > 0) then
				alarmNext_substree = subtree:add(content(0,alarmNext_len), "All Alarms Next Content")
			end
			local multiMessage
			while(content_pos < alarmNext_len) 
			do
				if(content(0+content_pos,2):uint() > 0) then
					local alarmNext_me_class = content(0+content_pos,2)
					multiMessage = alarmNext_substree:add(content(0+content_pos,32), "All Alarms Next Content(classId = " .. alarmNext_me_class:uint() .. ", instanceId = 0x" .. content(2+content_pos,2) .. ")")				

					multiMessage:add( alarmNext_me_class, "Managed Entity Class: " .. omci_def[alarmNext_me_class:uint()].me_class_name .. " (" .. alarmNext_me_class:uint() .. ")")
					multiMessage:add(content(2+content_pos,2), "Managed Entity Instance: " .. content(2+content_pos,2):uint() .. " (0x" .. content(2+content_pos,2) .. ")")
					multiMessage:add(content(4+content_pos,28), "BIT MAP: (" .. content(4+content_pos,28) .. ")")
				end
				content_pos = content_pos + 32
			end
		else
			if(content(0,2):uint() > 0) then
				local alarmNext_substree = subtree:add(content(0,32), "All Alarms Next Content")
				local alarmNext_me_class = content(0,2)
				alarmNext_substree:add( alarmNext_me_class, "Managed Entity Class: " .. omci_def[alarmNext_me_class:uint()].me_class_name .. " (" .. alarmNext_me_class:uint() .. ")")
				alarmNext_substree:add(content(2,2), "Managed Entity Instance: " .. content(2,2):uint() .. " (0x" .. content(2,2) .. ")")
				alarmNext_substree:add(content(4,28), "BIT MAP: (" .. content(4,28) .. ")")
			end
		end
	end
	
	if(msg_type_mt == "Synchronize Time" and msg_type_ar == 1 and msg_type_ak == 0) then
		if((dev_id:uint() == 0x0b and msgLen:uint() >=7) or dev_id:uint() == 0x0a) then
			local syncTime_subtree = subtree:add(content(0,7), "Synchronize Time Set Content")
			syncTime_subtree:add(content(0,2), "Year: " .. content(0,2):uint())
			syncTime_subtree:add(content(2,1), "Month(1~12): " .. content(2,1):uint())
			syncTime_subtree:add(content(3,1), "Day of Month(1~31): " .. content(3,1):uint())
			syncTime_subtree:add(content(4,1), "Hour of Day(0~23): " .. content(4,1):uint())
			syncTime_subtree:add(content(5,1), "Minute of Hour(0~59): " .. content(5,1):uint())
			syncTime_subtree:add(content(6,1), "Second of Minute(0~59): " .. content(6,1):uint())
		end
	end
	
	if(msg_type_mt == "Synchronize Time" and msg_type_ar == 0 and msg_type_ak == 1) then
		local contentLen=2
		if(dev_id:uint() == 0x0b) then
			contentLen = msgLen:uint()
		end
		local syncTime_subtree = subtree:add(content(0,contentLen), "Synchronize Time Response Content")
		result_code = content(0,1):uint()
		syncTime_subtree:add(content(0,1), "Result: " .. msg_result[content(0,1):uint()] .. " (" .. content(0,1) .. ")")
		if((dev_id:uint() == 0x0b and msgLen:uint() >1) or dev_id:uint() == 0x0a) then
			if(content(0,1):uint() == 0) then
				syncTime_subtree:add(content(1,1), "Successfully Result: " .. syncTime_success_result[content(1,1):uint()] .. " (" .. content(1,1) .. ")")
			end
		end
	end

	if(msg_type_mt == "Test" and msg_type_ar == 1 and msg_type_ak == 0) then
		if( dev_id:uint() == 0x0b) then -- ITU-T G988 XGPON 
			if( me_class:uint() == 263 ) then -- ANI-G
				subtree:add(content(0,2), "Size of message content field: " .. content(0,2))  
				subtree:add(content(2,1), "Test to perform: " .. test_message_name[content(2,1):uint()] .. " (" .. content(2,1) .. ")")
			end
		elseif( dev_id:uint() == 0x0a) then -- ITU-T G984.4 GPON 
			if( me_class:uint() == 263 ) then -- ANI-G
				subtree:add(content(0,1), "Test to perform: " .. test_message_name[content(0,1):uint()] .. " (" .. content(0,1) .. ")")
			end
		end
	end

	if(msg_type_mt == "Test Result" and msg_type_ar == 0 and msg_type_ak == 0 ) then	
		local content_subtree = subtree:add(content, "Test report")
		if( me_class_name == "ANI-G" ) then
			if( content(0,1):uint() == 1 ) then
				content_subtree:add(content(0,3), "Test " .. string.format("%2.2d: ", content(0,1):uint()) .. "Power feed voltage = " .. content(1,2):int() * 20 .. " mV (0x" .. content(1,2) .. ")")
			else
				content_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Unexpected 0x" .. content(0,1) .. " test at this location " )
			end
			if( content(3,1):uint() == 3 ) then
				if( content(4,2):int() ~= 0 ) then
					content_subtree:add(content(3,3), "Test " .. string.format("%2.2d: ", content(3,1):uint()) .. "Received optical power = " .. content(4,2):int() * 0.002 - 30 .. " dBm (0x" .. content(4,2) .. ")")		
				else
					content_subtree:add(content(3,3), "Test " .. string.format("%2.2d: ", content(3,1):uint()) .. "Received optical power: Not supported")
				end
			else
				content_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Unexpected 0x" .. content(3,1) .. " test at this location " )
			end		
			if( content(6,1):uint() == 5 ) then
				if( content(7,2):int() ~= 0 ) then
					content_subtree:add(content(6,3), "Test " .. string.format("%2.2d: ", content(6,1):uint()) .. "Transmitted optical power = " .. content(7,2):int() * 0.002 - 30 .. " dBm (0x" .. content(7,2) .. ")")		
				else
					content_subtree:add(content(6,3), "Test " .. string.format("%2.2d: ", content(6,1):uint()) .. "Transmitted optical power: Not supported" )
				end
			else
				content_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Unexpected 0x" .. content(6,1) .. " test at this location " )
			end		
			if( content(9,1):uint() == 9 ) then
				content_subtree:add(content(9,3), "Test " .. string.format("%2.2d: ", content(9,1):uint()) .. "Laser bias current = " .. content(10,2):int() * 2 .. " uA (0x" .. content(10,2) .. ")")		
			else
				content_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Unexpected 0x" .. content(9,1) .. " test at this location " )
			end		
			if( content(12,1):uint() == 12 ) then
				content_subtree:add(content(12,3), "Test " .. string.format("%2.2d: ", content(12,1):uint()) .. "Temperature = " .. content(13,2):int() / 256.0 .. " deg C (0x" .. content(13,2) .. ")")		
			else
				content_subtree:add_expert_info( PI_MALFORMED, PI_ERROR, "Unexpected 0x" .. content(13,1) .. " test at this location " )
			end		
		else
			subtree:add(content, "Test Result for ME Class " .. me_class_name .. " is not implemented!")
		end
	end

	if(msg_type_mt == "Alarm" and msg_type_ar == 0 and msg_type_ak == 0 ) then
		local alarmContentLen=32
		if(dev_id:uint() == 0x0b) then
			alarmContentLen = 29
		end
		local alarm_subtree = subtree:add(content(0,alarmContentLen), "Alarms")
		local alarm_set = false
		for i = 0, 27 do --loop through all alarms
			for j = 0, 7 do
				if(content(i,1):bitfield(j,1) == 1) then
					alarm_subtree:add(content(i,1), "Alarm number " .. i*8+j .. " is set")
					alarm_set = true
				end
			end
		end
		if( alarm_set == false) then
			alarm_subtree:add("All alarms cleared")
		end
		if(dev_id:uint() == 0x0a) then
			alarm_subtree:add(content(28,3), "Padding")
			alarm_subtree:add(content(31,1), "Sequence number: 0x" .. content(31,1) )
		else
			alarm_subtree:add(content(28,1), "Sequence number: 0x" .. content(28,1) )
		end
	end
	
	if(msg_type_mt == "Attribute Value Change" and msg_type_ar == 0 and msg_type_ak == 0 ) then	
		local attribute_mask = content(0, 2)
		local attributemask_subtree = subtree:add(attribute_mask, "Attribute Mask (0x" .. attribute_mask .. ")" )
		attributemask_subtree:add(attribute_mask, tostring(BinDecHex.Hex2Bin(tostring(attribute_mask))))
		if(dev_id:uint() == 0x0a) then
			content_subtree = subtree:add(content(2,30), "Attribute List")
		else
			content_subtree = subtree:add(content(2,msgLen:uint()-2), "Attribute List")
		end
		local attributes = {}
		local attribute_offset = 0
		attributes = omci_def[me_class:uint()]
		attribute_offset=2
		for i = 1,#attributes do
			local attr = attributes[i]
			if attribute_mask:bitfield(i-1,1) == 1 then
				local attr_bytes = content(attribute_offset, attr.length)
				content_subtree:add(attr_bytes, string.format("%2.2d", i) .. ": " .. attr.attname .. " (" .. attr_bytes .. ")")
				attribute_offset = attribute_offset + attr.length
			end
		end
	end
	
	
	if(dev_id:uint() == 0x0b) then
		local trailerLen = buffer:len() - (msgLen:uint()+10)
		if (trailerLen > 0) then
			if (trailerLen > 4) then
				trailerLen = 4
			end
			local trailer = buffer(msgLen:uint()+10, trailerLen)
			local trailer_subtree = subtree:add(trailer(0,trailerLen), "Trailer")
			trailer_subtree:add(trailer(0,trailerLen), "CRC32: 0x" .. trailer(0,trailerLen))
		end
	else
		offset = offset + 32		
		-- OMCI Trailer (if any)
		
		local trailer = buffer(offset, buffer:len()-40)
		local trailer_subtree = subtree:add(trailer, "Trailer")
		trailer_subtree:add(f.cpcsuu_cpi, trailer(0,2))
		trailer_subtree:add(f.cpcssdu_length, trailer(2,2))
		if( buffer:len() > 46) then
			trailer_subtree:add(f.crc32, trailer(4,4))
		end
	end

	if( msg_type_ar == 0 ) then
		msg_type_mt = "ONU< " .. msg_type_mt
	else 
		msg_type_mt = "OLT> " .. msg_type_mt
	end

	while msg_type_mt:len() < 25 do  -- Padding to align ME classes
		msg_type_mt = msg_type_mt .. " "
	end
	
	if( msg_type_ar == 0 and result_code ~= 0 ) then
		msg_type_mt = "[ERROR]" .. msg_type_mt
	end
	
    pinfo.cols.info:set(msg_type_mt .. " - " .. me_class_name .. " (" .. timestamp_date  .. ")" )
	subtree:append_text (", " .. msg_type_mt .. " - " .. me_class_name )	-- at the top of the OMCI tree
end

-- Register the dissector
local ether_table = DissectorTable.get( "ethertype" )
ether_table:add(0x88B5, omciproto) 

