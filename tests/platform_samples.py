"""Representative command output for the target platforms, used to sanity-check the starter drafts.

Written to match how each platform prints its configuration (lab addresses only):
  CAT9300_*  Catalyst 9300, IOS-XE 17.9
  CAT8300_*  Catalyst 8300, IOS-XE 17.9
  N9K_*      Nexus 93180YC-FX3 / 9336C-FX2, NX-OS 10.3

*_HARDENED is configured the way the STIG check text asks; *_DEFAULT is close to factory settings.
"""

BANNER = """You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations."""

AAA_IOS = """aaa new-model
!
aaa group server tacacs+ ISE
 server name ISE1
 server name ISE2
!
aaa authentication login default group ISE local
aaa authentication dot1x default group ISE
aaa authorization exec default group ISE local
aaa accounting exec default start-stop group ISE
aaa accounting commands 15 default start-stop group ISE
!
aaa common-criteria policy PASSWORD_POLICY
 min-length 15
 upper-case 1
 lower-case 1
 numeric-count 1
 special-case 1
 char-changes 8
!
aaa session-id common"""

MGMT_IOS = f"""ip http secure-server
ip http max-connections 2
ip http timeout-policy idle 300 life 86400 requests 10000
no ip http server
ip ssh version 2
ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256
ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
!
ip access-list extended MGMT_NET
 10 permit ip 10.10.100.0 0.0.0.255 any
 20 deny   ip any any log-input
!
logging host 10.10.50.10
logging host 10.10.50.11
!
snmp-server group V3GROUP v3 priv read V3READ
snmp-server view V3READ iso included
snmp-server host 10.10.50.20 version 3 priv V3USER
!
tacacs server ISE1
 address ipv4 10.10.50.30
 key 7 0822455D0A16
tacacs server ISE2
 address ipv4 10.10.50.31
 key 7 0822455D0A16
!
banner login ^C
{BANNER}
^C
!
line con 0
 exec-timeout 5 0
 stopbits 1
line vty 0 4
 session-limit 2
 access-class MGMT_NET in
 exec-timeout 5 0
 transport input ssh
line vty 5 31
 transport input none
!
ntp authentication-key 1 hmac-sha2-256 104D000A0618 7
ntp authenticate
ntp trusted-key 1
ntp server 10.10.50.40 key 1
ntp server 10.10.50.41 key 1
!
event manager applet BACKUP_CONFIG authorization bypass
 event syslog pattern "%SYS-5-CONFIG_I"
 action 1.0 cli command "enable"
 action 2.0 cli command "copy running-config scp://backup@10.10.50.50/$_info_routername-config"
!
archive
 log config
  logging enable
  logging size 1000
!
end"""

CAT9300_HARDENED = f"""Building configuration...

Current configuration : 18233 bytes
!
version 17.9
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
no service pad
platform punt-keepalive disable-kernel-core
!
hostname SW-ACCESS-01
!
vrf definition Mgmt-vrf
 !
 address-family ipv4
 exit-address-family
!
logging buffered 64000 informational
logging persistent url flash:/syslog size 134217728 filesize 16384
logging userinfo
no logging console
enable secret 9 $9$abcdefghijklmn
!
{AAA_IOS}
boot system switch all flash:packages.conf
switch 1 provision c9300-48p
!
ip routing
!
no ip domain lookup
ip domain name example.mil
!
login block-for 900 attempts 3 within 120
login on-failure log
login on-success log
!
ip dhcp snooping vlan 10,20
ip dhcp snooping
ip arp inspection vlan 10,20
!
crypto pki trustpoint SLA-TrustPoint
 enrollment pkcs12
 revocation-check crl
!
crypto pki trustpoint DOD_ID_CA
 enrollment url http://ca.example.mil/certsrv/mscep/mscep.dll
 revocation-check crl
!
license boot level network-advantage addon dna-advantage
!
dot1x system-auth-control
no cdp run
!
spanning-tree mode rapid-pvst
spanning-tree portfast edge bpduguard default
spanning-tree loopguard default
spanning-tree extend system-id
memory free low-watermark processor 134344
!
file prompt quiet
username breakglass privilege 15 common-criteria-policy PASSWORD_POLICY secret 9 $9$zyxwvutsrq
!
redundancy
 mode sso
udld aggressive
!
vlan 999
 name PARKING
!
class-map match-all VOICE
 match ip dscp ef
class-map match-all SCAVENGER
 match ip dscp cs1
!
policy-map QOS_OUT
 class VOICE
  priority level 1 percent 10
 class SCAVENGER
  bandwidth remaining percent 1
 class class-default
  bandwidth remaining percent 89
policy-map system-cpp-policy
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 no ip address
 shutdown
 negotiation auto
!
interface GigabitEthernet1/0/1
 description ACCESS - USER PORT
 switchport access vlan 10
 switchport mode access
 switchport block unicast
 ip verify source
 authentication port-control auto
 mab
 dot1x pae authenticator
 spanning-tree portfast
 storm-control broadcast level 1.00
 service-policy output QOS_OUT
!
interface GigabitEthernet1/0/2
 switchport access vlan 999
 switchport mode access
 shutdown
!
interface TenGigabitEthernet1/1/1
 description UPLINK - DIST-SW-01 Te2/0/14
 switchport trunk native vlan 900
 switchport trunk allowed vlan 10,20,100
 switchport mode trunk
 switchport nonegotiate
 ip dhcp snooping trust
 ip arp inspection trust
 udld port aggressive
 service-policy output QOS_OUT
!
interface AppGigabitEthernet1/0/1
 switchport mode trunk
!
interface Vlan1
 no ip address
 shutdown
!
interface Vlan100
 description MGMT
 ip address 10.10.100.11 255.255.255.0
 no ip redirects
 no ip unreachables
 no ip proxy-arp
!
control-plane
 service-policy input system-cpp-policy
!
{MGMT_IOS}"""

CAT9300_DEFAULT = """version 17.9
service timestamps debug datetime msec
service timestamps log datetime msec
service call-home
platform punt-keepalive disable-kernel-core
!
hostname Switch
!
no aaa new-model
switch 1 provision c9300-48p
!
crypto pki trustpoint TP-self-signed-1234567
 enrollment selfsigned
!
spanning-tree mode rapid-pvst
spanning-tree extend system-id
!
username admin privilege 15 password 0 cisco
username ops privilege 15 password 0 cisco
!
interface GigabitEthernet1/0/1
!
interface GigabitEthernet1/0/2
 switchport mode access
 shutdown
!
interface TenGigabitEthernet1/1/1
 switchport mode trunk
!
interface Vlan1
 ip address 10.1.1.10 255.255.255.0
!
ip http server
ip http secure-server
!
snmp-server community public RO
!
line con 0
line vty 0 4
 login
 transport input ssh telnet
line vty 5 15
 login
!
call-home
 contact-email-addr sch-smart-licensing@cisco.com
 profile "CiscoTAC-1"
  active
!
end"""

CAT8300_HARDENED = f"""version 17.9
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
platform qfp utilization monitor load 80
!
hostname RTR-01
!
boot-start-marker
boot-end-marker
!
logging buffered 64000 informational
logging userinfo
enable secret 9 $9$abcdefghijklmn
!
{AAA_IOS}
!
login block-for 900 attempts 3 within 120
login on-failure log
login on-success log
!
crypto pki trustpoint DOD_ID_CA
 enrollment terminal
 revocation-check crl
!
license udi pid C8300-1N1S-6T sn FDO12345678
memory free low-watermark processor 69584
file prompt quiet
username breakglass privilege 15 common-criteria-policy PASSWORD_POLICY secret 9 $9$zyxwvutsrq
!
redundancy
!
key chain OSPF_KEY
 key 1
  key-string 7 0822455D0A16
  accept-lifetime 00:00:00 Jan 1 2026 duration 180
  send-lifetime 00:00:00 Jan 1 2026 duration 180
  cryptographic-algorithm hmac-sha-256
!
class-map match-all SCAVENGER
 match ip dscp cs1
policy-map QOS_OUT
 class SCAVENGER
  bandwidth percent 5
policy-map COPP
 class class-default
  police 64000 conform-action transmit exceed-action drop
!
interface GigabitEthernet0/0/0
 description WAN
 ip address 192.0.2.2 255.255.255.252
 no ip redirects
 no ip unreachables
 no ip proxy-arp
 negotiation auto
 service-policy output QOS_OUT
!
interface GigabitEthernet0/0/1
 description LAN
 ip address 10.20.0.1 255.255.255.0
 no ip redirects
 no ip unreachables
 no ip proxy-arp
 ip ospf authentication key-chain OSPF_KEY
 negotiation auto
!
interface GigabitEthernet0/0/2
 no ip address
 shutdown
 negotiation auto
!
router ospf 1
 router-id 10.20.0.1
!
control-plane
 service-policy input COPP
!
line aux 0
 no exec
 transport input none
!
{MGMT_IOS}"""

CAT8300_DEFAULT = """version 17.9
service timestamps debug datetime msec
service timestamps log datetime msec
service call-home
!
hostname Router
!
no aaa new-model
!
interface GigabitEthernet0/0/0
 ip address dhcp
 negotiation auto
!
interface GigabitEthernet0/0/1
 ip address 10.20.0.1 255.255.255.0
 negotiation auto
!
ip http server
ip http secure-server
!
line con 0
line aux 0
line vty 0 4
 login
 transport input ssh
!
end"""

N9K_HARDENED = f"""!Command: show running-config
!Running configuration last done at: Thu Oct  1 10:00:00 2026
!Time: Thu Oct  1 10:05:00 2026

version 10.3(4a) Bios:version 05.47
hostname NX-LEAF-01
policy-map type network-qos jumbo
  class type network-qos class-default
    mtu 9216
vdc NX-LEAF-01 id 1
  limit-resource vlan minimum 16 maximum 4094

feature tacacs+
feature scp-server
feature interface-vlan
feature dhcp
feature lacp
feature udld

username admin password 5 $5$KDhHZi$abcdef  role network-admin
ip domain-lookup
copp profile strict
snmp-server user NETOPS network-operator auth sha 0x1234 priv aes-128 0x5678 localizedkey
snmp-server host 10.30.50.20 traps version 3 priv NETOPS
ntp authentication-key 1 md5 swwX 7
ntp server 10.30.50.40 use-vrf management key 1
ntp server 10.30.50.41 use-vrf management key 1
ntp authenticate
ntp trusted-key 1
tacacs-server host 10.30.50.30 key 7 "fewhg123"
tacacs-server host 10.30.50.31 key 7 "fewhg123"
aaa group server tacacs+ ISE
    server 10.30.50.30
    server 10.30.50.31
    use-vrf management
aaa authentication login default group ISE
aaa authentication login console group ISE
aaa accounting default group ISE

class-map type control-plane match-any copp-system-p-class-critical
  match access-group name copp-system-p-acl-bgp
policy-map type control-plane copp-system-p-policy-strict
  class copp-system-p-class-critical
    set cos 7
    police cir 36000 kbps bc 1280000 bytes
control-plane
  service-policy input copp-system-p-policy-strict

ip access-list MGMT_NET
  10 permit ip 10.30.100.0/24 any
  20 deny ip any any log
logging ip access-list cache entries 8000
ssh login-attempts 3
ssh ciphers aes256-ctr aes128-ctr
ssh macs hmac-sha2-256 hmac-sha2-512
no ip source-route
no cdp enable
spanning-tree port type edge bpduguard default
spanning-tree loopguard default
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
vlan 1,10,999
vlan 999
  name PARKING

vrf context management
  ip route 0.0.0.0/0 10.30.100.1

interface Vlan1

interface Vlan10
  no shutdown
  no ip redirects
  ip address 10.30.10.1/24
  no ip arp gratuitous request

interface Ethernet1/1
  description ACCESS - SERVER-01 eth0
  switchport access vlan 10
  spanning-tree port type edge
  switchport block unicast
  ip verify source dhcp-snooping-vlan
  storm-control broadcast level 1.00
  no shutdown

interface Ethernet1/2
  shutdown
  switchport access vlan 999

interface Ethernet1/3

interface Ethernet1/49
  description UPLINK - SPINE-01 Eth1/1
  switchport mode trunk
  switchport trunk native vlan 900
  switchport trunk allowed vlan 10,20
  ip dhcp snooping trust
  ip arp inspection trust
  no shutdown

interface mgmt0
  vrf member management
  ip access-group MGMT_NET in
  ip address 10.30.100.11/24
line console
  exec-timeout 5
line vty
  session-limit 2
  exec-timeout 5
  access-class MGMT_NET in
boot nxos bootflash:/nxos64-cs.10.3.4a.M.bin
logging logfile messages 6 size 4194304
logging server 10.30.50.10 6 use-vrf management
logging server 10.30.50.11 6 use-vrf management
logging level authpri 6
no logging console
banner motd ^
{BANNER}
^
event manager applet BACKUP_CONFIG
  event syslog pattern "VSHD_SYSLOG_CONFIG_I"
  action 1 cli copy running-config scp://backup@10.30.50.50/nx.cfg vrf management
"""

N9K_DEFAULT = """!Command: show running-config
version 10.3(4a) Bios:version 05.47
hostname switch
feature telnet
feature lldp

username admin password 5 $5$abc  role network-admin
username ops password 5 $5$def  role network-operator
snmp-server user admin network-admin auth md5 0x1111 priv 0x2222 localizedkey
no password strength-check
vlan 1

vrf context management

interface Vlan1

interface Ethernet1/1

interface Ethernet1/49
  switchport mode trunk

interface mgmt0
  vrf member management
  ip address 10.30.100.11/24
line console
line vty
boot nxos bootflash:/nxos64-cs.10.3.4a.M.bin
"""

SHOW = {
    "CAT9300_HARDENED": {
        "show snmp user": "User name: V3USER\nEngine ID: 800000090300F87B204E5C00\nstorage-type: nonvolatile        "
                          "active\nAuthentication Protocol: SHA\nPrivacy Protocol: AES256\nGroup-name: V3GROUP",
        "show vtp status": "VTP Version capable             : 1 to 3\nVTP version running             : 1\n"
                           "VTP Domain Name                 : \nVTP Operating Mode                : Off",
        "show vtp password": "The VTP password is not configured.",
        "show interfaces switchport": "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: static access\n"
                                      "Negotiation of Trunking: Off\n\nName: Te1/1/1\nSwitchport: Enabled\n"
                                      "Administrative Mode: trunk\nNegotiation of Trunking: Off",
        "show vlan brief": "VLAN Name                             Status    Ports\n---- ---- ----\n"
                           "1    default                          active    \n"
                           "10   USERS                            active    Gi1/0/1\n"
                           "999  PARKING                          active    Gi1/0/2",
        "show version": "Cisco IOS XE Software, Version 17.09.04a\nCisco IOS Software [Cupertino], Catalyst L3 Switch",
        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\n"
                                   "Vlan1                  unassigned      YES NVRAM  administratively down down    \n"
                                   "Vlan100                10.10.100.11    YES NVRAM  up                    up      \n"
                                   "GigabitEthernet1/0/3   unassigned      YES unset  down                  down    ",
    },
    "CAT9300_DEFAULT": {
        "show snmp user": "",
        "show vtp status": "VTP Version capable             : 1 to 3\nVTP Operating Mode                : Server",
        "show vtp password": "The VTP password is not configured.",
        "show interfaces switchport": "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: dynamic auto\n"
                                      "Negotiation of Trunking: On",
        "show vlan brief": "VLAN Name                             Status    Ports\n"
                           "1    default                          active    Gi1/0/1, Gi1/0/2",
        "show version": "Cisco IOS XE Software, Version 17.03.05\n",
        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\n"
                                   "Vlan1                  10.1.1.10       YES NVRAM  down                  down    ",
    },
    "CAT8300_HARDENED": {
        "show snmp user": "User name: V3USER\nAuthentication Protocol: SHA\nPrivacy Protocol: AES256\n",
        "show version": "Cisco IOS XE Software, Version 17.12.04\nCisco IOS Software [Dublin], c8000be",
        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\n"
                                   "GigabitEthernet0/0/0   192.0.2.2       YES NVRAM  up                    up      \n"
                                   "GigabitEthernet0/0/1   10.20.0.1       YES NVRAM  up                    up      \n"
                                   "GigabitEthernet0/0/2   unassigned      YES unset  administratively down down    ",
    },
    "CAT8300_DEFAULT": {
        "show snmp user": "",
        "show version": "Cisco IOS XE Software, Version 17.06.01\n",
        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\n"
                                   "GigabitEthernet0/0/1   10.20.0.1       YES NVRAM  down                  down    ",
    },
    "N9K_HARDENED": {
        "show version": "Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 10.3(4a)\n",
        "show ip interface brief vrf all": "IP Interface Status for VRF \"default\"(1)\nInterface            IP Address      "
                                           "Interface Status\nVlan10               10.30.10.1      protocol-up/link-up/admin-up",
    },
    "N9K_DEFAULT": {
        "show version": "Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 9.3(5)\n",
        "show ip interface brief vrf all": "IP Interface Status for VRF \"management\"(2)\nInterface            IP Address "
                                           "     Interface Status\nmgmt0                10.30.100.11    "
                                           "protocol-down/link-down/admin-up",
    },
}

CONFIGS = {"CAT9300_HARDENED": CAT9300_HARDENED, "CAT9300_DEFAULT": CAT9300_DEFAULT,
           "CAT8300_HARDENED": CAT8300_HARDENED, "CAT8300_DEFAULT": CAT8300_DEFAULT,
           "N9K_HARDENED": N9K_HARDENED, "N9K_DEFAULT": N9K_DEFAULT}


def outputs(name):
    """Evidence dict for the rule engine: {command: {"status", "text"}}"""
    out = {"show running-config": CONFIGS[name]}
    out.update(SHOW[name])
    return {cmd: {"status": "ok", "text": text} for cmd, text in out.items()}
