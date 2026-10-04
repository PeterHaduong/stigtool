"""Hardening scripts: fix commands per rule, and the scripts generated from them.

Every rule can carry two blocks of fix commands (rule["fix"] = {"low": text, "high": text}):
  low   - low impact: banners, logging, archive, timestamps, disabling legacy services...
  high  - impactful: AAA, SSH algorithms, vty access, port / STP / 802.1x settings, SNMP, routing...
Scripts are always written as two separate files so the low-impact one can be pushed on its own.

Inside fix commands:
  <SOMETHING>              a site value to fill in; the script lists every one at the top as EDIT BEFORE USE
  {each failing section}   on its own line, followed by indented commands: repeat those commands under every
                           section (usually an interface) that failed on the device. Without assessment results
                           a placeholder header is written instead.
  {each failing section of condition 2}
                           the same, but only for sections that failed condition 2 of the rule (numbered as in the
                           rule editor). Lets one rule add a command where it is missing (e.g. trust on uplinks)
                           and remove it where it must not be (e.g. trust on access ports).
  ! text                   a comment, copied into the script
"""
import re

import assess
import store

EACH = "{each failing section}"
EACH_RE = re.compile(r"^\{each failing section(?: of condition (\d+))?\}$", re.I)
PLACEHOLDER_RE = re.compile(r"<[A-Z0-9_ /.-]+>")
IMPACT = {"low": "LOW IMPACT", "high": "IMPACTFUL"}
HEADER_WARNING = {
    "low": ["! Low-impact changes (banners, logging, archive, timestamps, legacy services).",
            "! Still review before use and test on one device first."],
    "high": ["! *** IMPACTFUL CHANGES - these can disconnect management sessions, lock out accounts or change how",
             "! *** traffic is forwarded. Apply in a maintenance window, on ONE device first, with console or",
             "! *** out-of-band access available. Review every line."],
}

DOD_BANNER = """You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."""


def F(low=(), high=()):
    return {"low": "\n".join(low), "high": "\n".join(high)}


def each(*cmds):
    return [EACH] + [f" {c}" for c in cmds]


# ---------------------------------------------------------------- IOS-XE fix commands (Catalyst 9300 / 8300)

ARCHIVE = ["archive", " log config", "  logging enable", "  logging size 1000"]
IOS_LEGACY = ["no service pad", "no service finger", "no service tcp-small-servers", "no service udp-small-servers",
              "no ip finger", "no ip identd", "no ip bootp server", "no ip dns server", "no ip rcmd rcp-enable",
              "no ip rcmd rsh-enable", "no service config", "no ip boot server"]
ACL_LOG = each("! add 'log-input' to every deny statement in this ACL, e.g. <SEQ> deny ip any any log-input")

FIX_IOSXE = {
    "CISC-ND-000010": F(low=["ip http max-connections 2"], high=["line vty 0 4", " session-limit 2"]),
    **{k: F(low=ARCHIVE) for k in ("CISC-ND-000090", "CISC-ND-000100", "CISC-ND-000110", "CISC-ND-000120",
                                   "CISC-ND-000330", "CISC-ND-000880", "CISC-ND-001250", "CISC-ND-001270")},
    "CISC-ND-000140": F(high=["ip access-list extended MGMT_NET", " permit ip <MGMT_SUBNET> <MGMT_WILDCARD> any",
                              " deny ip any any log-input", "line vty 0 4", " access-class MGMT_NET in"]),
    "CISC-ND-000150": F(high=["login block-for 900 attempts 3 within 120"]),
    "CISC-ND-000160": F(low=["banner login ^C"] + DOD_BANNER.splitlines() + ["^C"]),
    "CISC-ND-000210": F(low=["logging userinfo"] + ARCHIVE),
    "CISC-ND-000280": F(low=["service timestamps log datetime msec localtime show-timezone"]),
    "CISC-ND-000290": F(high=ACL_LOG),
    **{k: F(low=["file privilege 15"]) for k in ("CISC-ND-000380", "CISC-ND-000390", "CISC-ND-000460")},
    "CISC-ND-000470": F(low=IOS_LEGACY, high=["no ip http server", "no service call-home"]),
    "CISC-ND-000490": F(high=["! remove every local account except the account of last resort:",
                              "! no username <EXTRA_ACCOUNT>",
                              "aaa authentication login default group <AAA_GROUP> local"]),
    "CISC-ND-000550": F(low=["aaa common-criteria policy PASSWORD_POLICY", " min-length 15"]),
    "CISC-ND-000570": F(low=["aaa common-criteria policy PASSWORD_POLICY", " upper-case 1"]),
    "CISC-ND-000580": F(low=["aaa common-criteria policy PASSWORD_POLICY", " lower-case 1"]),
    "CISC-ND-000590": F(low=["aaa common-criteria policy PASSWORD_POLICY", " numeric-count 1"]),
    "CISC-ND-000600": F(low=["aaa common-criteria policy PASSWORD_POLICY", " special-case 1"]),
    "CISC-ND-000610": F(low=["aaa common-criteria policy PASSWORD_POLICY", " char-changes 8"]),
    "CISC-ND-000620": F(low=["service password-encryption"],
                        high=["no enable password", "enable algorithm-type scrypt secret <ENABLE_SECRET>"]),
    "CISC-ND-000720": F(low=["line con 0", " exec-timeout 5 0", "line vty 0 4", " exec-timeout 5 0",
                             "ip http timeout-policy idle 300 life 86400 requests 10000"]),
    "CISC-ND-000980": F(low=["logging buffered 64000 informational"]),
    "CISC-ND-001000": F(low=["logging trap critical"]),
    "CISC-ND-001030": F(low=["ntp server <NTP_SERVER_1>", "ntp server <NTP_SERVER_2>"]),
    "CISC-ND-001130": F(high=["snmp-server group <SNMP_GROUP> v3 priv read <SNMP_VIEW>",
                              "snmp-server user <SNMP_USER> <SNMP_GROUP> v3 auth sha <AUTH_PASSWORD> priv aes 256 "
                              "<PRIV_PASSWORD>", "no snmp-server community <OLD_COMMUNITY>"]),
    "CISC-ND-001140": F(high=["snmp-server group <SNMP_GROUP> v3 priv read <SNMP_VIEW>",
                              "snmp-server user <SNMP_USER> <SNMP_GROUP> v3 auth sha <AUTH_PASSWORD> priv aes 256 "
                              "<PRIV_PASSWORD>"]),
    "CISC-ND-001150": F(high=["ntp authentication-key 1 hmac-sha2-256 <NTP_KEY>", "ntp authenticate",
                              "ntp trusted-key 1", "ntp server <NTP_SERVER_1> key 1", "ntp server <NTP_SERVER_2> key 1"]),
    "CISC-ND-001200": F(high=["ip ssh version 2", "ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256"]),
    "CISC-ND-001210": F(high=["ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr"]),
    "CISC-ND-001260": F(low=["login on-failure log", "login on-success log"]),
    "CISC-ND-001370": F(high=["tacacs server <AAA_SERVER_1>", " address ipv4 <AAA_IP_1>", " key <AAA_KEY>",
                              "tacacs server <AAA_SERVER_2>", " address ipv4 <AAA_IP_2>", " key <AAA_KEY>",
                              "aaa group server tacacs+ <AAA_GROUP>", " server name <AAA_SERVER_1>",
                              " server name <AAA_SERVER_2>", "aaa authentication login default group <AAA_GROUP> local"]),
    "CISC-ND-001410": F(low=["file prompt quiet", "event manager applet BACKUP_CONFIG authorization bypass",
                             " event syslog pattern \"%SYS-5-CONFIG_I\"", " action 1 cli command \"enable\"",
                             " action 2 info type routername",
                             " action 3 cli command \"copy running-config scp://<SCP_USER>@<SCP_SERVER>/<SCP_PATH>/"
                             "$_info_routername-running-config\""]),
    "CISC-ND-001440": F(high=["! enroll with a DoD / DoD-approved CA and remove self-signed trustpoints:",
                              "crypto pki trustpoint <DOD_CA_TRUSTPOINT>", " enrollment url <CA_ENROLLMENT_URL>",
                              " revocation-check crl", "! no crypto pki trustpoint <SELF_SIGNED_TRUSTPOINT>"]),
    "CISC-ND-001450": F(low=["logging host <SYSLOG_SERVER_1>", "logging host <SYSLOG_SERVER_2>"]),
    "CISC-ND-001470": F(high=["! upgrade the device to a Cisco-supported IOS-XE release (not a config change)"]),
    "CISC-RT-000050": F(high=["key chain <KEY_CHAIN>", " key 1", "  key-string <ROUTING_KEY>",
                              "  cryptographic-algorithm hmac-sha-256",
                              "  send-lifetime 00:00:00 <START_DATE> duration 180",
                              "  accept-lifetime 00:00:00 <START_DATE> duration 180",
                              "interface <ROUTING_INTERFACE>", " ip ospf authentication key-chain <KEY_CHAIN>"]),
    "CISC-RT-000060": F(high=["! shut down routed interfaces that are not in use:",
                              "interface <UNUSED_INTERFACE>", " shutdown"]),
    "CISC-RT-000090": F(low=["no service config", "! also remove any 'boot network' and 'cns' lines"]),
    "CISC-RT-000120": F(high=["! Catalyst 9300: keep the built-in 'policy-map system-cpp-policy' and tune rates;",
                              "! Catalyst 8300: build a CoPP policy-map and apply it:",
                              "control-plane", " service-policy input <COPP_POLICY>"]),
    "CISC-RT-000150": F(high=["no ip gratuitous-arps"]),
    "CISC-RT-000160": F(low=each("no ip directed-broadcast")),
    "CISC-RT-000170": F(low=each("no ip unreachables")),
    "CISC-RT-000180": F(low=each("no ip mask-reply")),
    "CISC-RT-000190": F(low=each("no ip redirects")),
    "CISC-RT-000200": F(high=each("! add 'log' or 'log-input' to every deny statement in this ACL")),
    "CISC-RT-000210": F(high=ACL_LOG),
    "CISC-RT-000220": F(high=ACL_LOG),
    "CISC-RT-000230": F(low=["line aux 0", " no exec", " transport input none"]),
    "CISC-RT-000235": F(low=["ip cef", "ipv6 cef"]),
    "CISC-RT-000236": F(low=["ipv6 hop-limit 64"]),
    "CISC-RT-000237": F(high=["! replace any FEC0::/10 (site-local) IPv6 addresses with global or ULA addresses"]),
    "CISC-RT-000360": F(high=["no lldp run"]),
    "CISC-RT-000370": F(high=["no cdp run", "! (IP phones use CDP for the voice VLAN - use per-interface "
                                            "'no cdp enable' on external interfaces instead if needed)"]),
    "CISC-RT-000380": F(high=each("no ip proxy-arp")),
    "CISC-RT-000470": F(high=["router bgp <ASN>", " neighbor <EBGP_PEER> ttl-security hops 1"]),
    "CISC-RT-000490": F(high=["! build the Bogon prefix list (see check text) and apply it inbound to every eBGP peer:",
                              "router bgp <ASN>", " neighbor <EBGP_PEER> prefix-list <BOGON_PREFIX_LIST> in"]),
    "CISC-RT-000500": F(high=["ip prefix-list <INBOUND_FILTER> seq <SEQ> deny <LOCAL_AS_PREFIX> le 32",
                              "router bgp <ASN>", " neighbor <EBGP_PEER> prefix-list <INBOUND_FILTER> in"]),
    "CISC-RT-000510": F(high=["router bgp <ASN>", " neighbor <CE_PEER> prefix-list <CUSTOMER_PREFIX_LIST> in"]),
    "CISC-RT-000520": F(high=["router bgp <ASN>", " neighbor <CE_PEER> prefix-list <ADVERTISE_PREFIX_LIST> out"]),
    "CISC-RT-000530": F(high=["router bgp <ASN>", " neighbor <EBGP_PEER> prefix-list <FILTER_CORE_PREFIXES> out"]),
    "CISC-RT-000540": F(high=["router bgp <ASN>", " bgp enforce-first-as"]),
    "CISC-RT-000550": F(high=["ip as-path access-list <AS_PATH_ACL> permit ^<CUSTOMER_AS>$",
                              "router bgp <ASN>", " neighbor <CE_PEER> filter-list <AS_PATH_ACL> in"]),
    "CISC-RT-000560": F(high=["router bgp <ASN>", " neighbor <EBGP_PEER> maximum-prefix <MAX_PREFIXES>"]),
    "CISC-RT-000570": F(high=["ip prefix-list FILTER_PREFIX_LENGTH seq 5 permit 0.0.0.0/0 ge 8 le 24",
                              "ip prefix-list FILTER_PREFIX_LENGTH seq 10 deny 0.0.0.0/0 le 32",
                              "router bgp <ASN>", " neighbor <EBGP_PEER> prefix-list FILTER_PREFIX_LENGTH in"]),
    "CISC-RT-000580": F(high=["router bgp <ASN>", " neighbor <IBGP_PEER> update-source Loopback0"]),
    "CISC-RT-000590": F(high=["mpls ldp router-id Loopback0 force"]),
    "CISC-RT-000600": F(high=["router ospf <OSPF_PROCESS>", " mpls ldp sync"]),
    "CISC-RT-000610": F(high=["ip rsvp signalling rate-limit period 30 burst 9 maxsize 2100 limit 50"]),
    "CISC-RT-000620": F(high=["no mpls ip propagate-ttl"]),
    "CISC-RT-000690": F(high=["! remove 'no-split-horizon' from VFI neighbor statements (mesh VPLS only)"]),
    "CISC-RT-000700": F(high=each("storm-control broadcast cir <STORM_CIR>")),
    "CISC-RT-000710": F(low=["ip igmp snooping"]),
    "CISC-RT-000720": F(high=["bridge-domain <BRIDGE_DOMAIN>", " mac limit maximum addresses <MAX_MACS>"]),
    "CISC-RT-000750": F(high=["ip options drop"]),
    "CISC-RT-000760": F(high=["! build the QoS class-maps / policy-map per the GIG QoS profile, then on each interface:",
                              "interface <INTERFACE>", " service-policy output <QOS_POLICY>"]),
    "CISC-RT-000770": F(high=["! build the QoS class-maps / policy-map per the GIG QoS profile, then on each interface:",
                              "interface <INTERFACE>", " service-policy output <QOS_POLICY>"]),
    "CISC-RT-000780": F(high=["class-map match-all SCAVENGER", " match ip dscp cs1", "policy-map <QOS_POLICY>",
                              " class SCAVENGER", "  bandwidth percent 5"]),
    "CISC-RT-000800": F(high=each("ip pim neighbor-filter <PIM_NEIGHBOR_ACL>")),
    "CISC-RT-000810": F(high=["interface <EDGE_INTERFACE>", " ip multicast boundary <MULTICAST_SCOPE_ACL>"]),
    "CISC-RT-000820": F(high=["ip pim accept-register list <PIM_REGISTER_ACL>", "ip pim register-rate-limit <RATE>"]),
    "CISC-RT-000830": F(high=["ip pim accept-register list <PIM_REGISTER_ACL>"]),
    "CISC-RT-000840": F(high=["ip pim accept-rp <RP_ADDRESS> <PIM_JOIN_ACL>"]),
    "CISC-RT-000850": F(high=["ip pim register-rate-limit <RATE>"]),
    "CISC-RT-000860": F(high=each("ip igmp access-group <IGMP_JOIN_ACL>")),
    "CISC-RT-000870": F(high=each("ip igmp access-group <IGMP_JOIN_ACL>")),
    "CISC-RT-000880": F(high=["ip igmp limit <IGMP_LIMIT>"]),
    "CISC-RT-000890": F(high=["ip pim spt-threshold infinity"]),
    "CISC-RT-000910": F(high=["ip msdp password peer <MSDP_PEER> <MSDP_KEY>"]),
    "CISC-RT-000920": F(high=["ip msdp sa-filter in <MSDP_PEER> list <INBOUND_SA_ACL>"]),
    "CISC-RT-000930": F(high=["ip msdp sa-filter out <MSDP_PEER> list <OUTBOUND_SA_ACL>"]),
    "CISC-RT-000940": F(high=["ip msdp sa-limit <MSDP_PEER> <SA_LIMIT>"]),
    "CISC-RT-000950": F(high=["ip msdp peer <MSDP_PEER> connect-source Loopback0"]),
    # ---- L2S (Catalyst 9300)
    "CISC-L2-000020": F(high=["dot1x system-auth-control", "{each failing section of condition 1}",
                              " authentication port-control auto", " dot1x pae authenticator", " mab"]),
    "CISC-L2-000030": F(high=["vtp mode off"]),
    "CISC-L2-000040": F(high=["! build the QoS policy per the site QoS design, then on each port:",
                              "interface <INTERFACE>", " service-policy output <QOS_POLICY>"]),
    "CISC-L2-000090": F(high=each("spanning-tree guard root")),
    "CISC-L2-000100": F(high=["spanning-tree portfast edge bpduguard default"]),
    "CISC-L2-000110": F(high=["spanning-tree loopguard default"]),
    "CISC-L2-000120": F(high=each("switchport block unicast")),
    "CISC-L2-000130": F(high=["ip dhcp snooping vlan <USER_VLANS>", "ip dhcp snooping",
                              "{each failing section of condition 3}", " ip dhcp snooping trust",
                              "{each failing section of condition 4}", " no ip dhcp snooping trust"]),
    "CISC-L2-000140": F(high=each("ip verify source")),
    "CISC-L2-000150": F(high=["ip arp inspection vlan <USER_VLANS>",
                              "{each failing section of condition 2}", " ip arp inspection trust",
                              "{each failing section of condition 3}", " no ip arp inspection trust"]),
    "CISC-L2-000160": F(high=each("storm-control broadcast level <STORM_LEVEL_PERCENT>")),
    "CISC-L2-000170": F(low=["ip igmp snooping"]),
    "CISC-L2-000180": F(high=["spanning-tree mode rapid-pvst"]),
    "CISC-L2-000190": F(high=["udld enable"]),
    "CISC-L2-000200": F(high=["! for every port showing 'Negotiation of Trunking: On':",
                              "interface <PORT>", " switchport mode <ACCESS_OR_TRUNK>", " switchport nonegotiate"]),
    "CISC-L2-000210": F(low=each("switchport access vlan <PARKING_VLAN>")),
    "CISC-L2-000220": F(high=["! move every port listed under VLAN 1 to its proper VLAN:",
                              "interface <PORT>", " switchport access vlan <USER_VLAN>"]),
    "CISC-L2-000230": F(high=each("switchport trunk allowed vlan remove 1")),
    "CISC-L2-000240": F(high=["! move management to a dedicated VLAN first, then:",
                              "interface Vlan1", " no ip address", " shutdown"]),
    "CISC-L2-000260": F(high=each("switchport trunk native vlan <NATIVE_VLAN>")),
    "CISC-L2-000250": F(high=["{each failing section of condition 1}", " switchport mode access",
                              " switchport nonegotiate"],
                        low=["{each failing section of condition 2}",
                             " ! label this port: description UPLINK - ... / DOWNLINK - ... / ACCESS - ..."]),
}


# ---------------------------------------------------------------- NX-OS fix commands (Nexus 9000)

NX_ACCT = F(low=["aaa accounting default group <AAA_GROUP>"])

FIX_NXOS = {
    "CISC-ND-000010": F(high=["line vty", "  session-limit 2"]),
    **{k: NX_ACCT for k in ("CISC-ND-000090", "CISC-ND-000100", "CISC-ND-000110", "CISC-ND-000120", "CISC-ND-000210",
                            "CISC-ND-000330", "CISC-ND-000880", "CISC-ND-000940", "CISC-ND-001240", "CISC-ND-001250",
                            "CISC-ND-001270")},
    "CISC-ND-000140": F(high=["ip access-list MGMT_NET", "  10 permit ip <MGMT_SUBNET_CIDR> any",
                              "  20 deny ip any any log", "interface mgmt0", "  ip access-group MGMT_NET in",
                              "line vty", "  access-class MGMT_NET in"]),
    "CISC-ND-000150": F(high=["ssh login-attempts 3"]),
    "CISC-ND-000160": F(low=["banner motd ^"] + DOD_BANNER.splitlines() + ["^"]),
    "CISC-ND-000290": F(low=["logging ip access-list cache entries 8000"],
                        high=each("! add 'log' to every deny statement in this ACL")),
    "CISC-ND-000470": F(high=["no feature telnet"]),
    "CISC-ND-000490": F(high=["! remove every local account except the account of last resort:",
                              "! no username <EXTRA_ACCOUNT>",
                              "! and remove any 'no aaa authentication login default fallback error local'"]),
    "CISC-ND-000530": F(high=["ssh macs hmac-sha2-256 hmac-sha2-512"]),
    **{k: F(low=["password strength-check"]) for k in ("CISC-ND-000570", "CISC-ND-000580", "CISC-ND-000590",
                                                         "CISC-ND-000600")},
    "CISC-ND-000720": F(low=["line console", "  exec-timeout 5", "line vty", "  exec-timeout 5"]),
    "CISC-ND-000980": F(low=["logging logfile messages 6 size 4194304"]),
    "CISC-ND-001000": F(low=["logging server <SYSLOG_SERVER_1> 6 use-vrf management"]),
    "CISC-ND-001030": F(low=["ntp server <NTP_SERVER_1> use-vrf management", "ntp server <NTP_SERVER_2> use-vrf management"]),
    "CISC-ND-001130": F(high=["snmp-server user <SNMP_USER> network-operator auth sha <AUTH_PASSWORD> priv aes-128 "
                              "<PRIV_PASSWORD>", "! remove or re-key the default 'admin' SNMP user (auth md5)",
                              "no snmp-server community <OLD_COMMUNITY>"]),
    "CISC-ND-001140": F(high=["snmp-server user <SNMP_USER> network-operator auth sha <AUTH_PASSWORD> priv aes-128 "
                              "<PRIV_PASSWORD>"]),
    "CISC-ND-001200": F(high=["ssh macs hmac-sha2-256 hmac-sha2-512"]),
    "CISC-ND-001210": F(high=["ssh ciphers aes256-ctr aes128-ctr"]),
    "CISC-ND-001220": F(high=["copp profile strict"]),
    "CISC-ND-001260": F(low=["logging level authpri 6", "logging logfile messages 6"]),
    "CISC-ND-001280": F(low=["logging level authpri 6"]),
    "CISC-ND-001310": F(low=["logging server <SYSLOG_SERVER_1> 6 use-vrf management"]),
    "CISC-ND-001370": F(high=["tacacs-server host <AAA_IP_1> key <AAA_KEY>", "tacacs-server host <AAA_IP_2> key <AAA_KEY>",
                              "aaa group server tacacs+ <AAA_GROUP>", "    server <AAA_IP_1>", "    server <AAA_IP_2>",
                              "    use-vrf management", "aaa authentication login default group <AAA_GROUP>",
                              "aaa authentication login console group <AAA_GROUP>"]),
    "CISC-ND-001410": F(low=["event manager applet BACKUP_CONFIG", "  event syslog pattern \"VSHD_SYSLOG_CONFIG_I\"",
                             "  action 1 cli copy running-config scp://<SCP_USER>@<SCP_SERVER>/<SCP_PATH>/nx-config "
                             "vrf management"]),
    "CISC-ND-001440": F(high=["! enroll with a DoD / DoD-approved CA (NX-OS uses cut-and-paste enrollment):",
                              "crypto ca trustpoint <DOD_CA_TRUSTPOINT>", "  enrollment terminal"]),
    "CISC-ND-001450": F(low=["logging server <SYSLOG_SERVER_1> 6 use-vrf management",
                             "logging server <SYSLOG_SERVER_2> 6 use-vrf management"]),
    "CISC-ND-001470": F(high=["! upgrade the switch to a Cisco-supported NX-OS release (not a config change)"]),
    # ---- L2S
    "CISC-L2-000020": F(high=["feature dot1x", "{each failing section of condition 1}", "  dot1x port-control auto"]),
    "CISC-L2-000080": F(high=["feature dot1x", "{each failing section of condition 1}", "  dot1x port-control auto"]),
    "CISC-L2-000030": F(high=["no feature vtp", "! or: vtp mode transparent"]),
    "CISC-L2-000060": F(low=["! confirm SPAN is available: monitor session <N> / source interface <PORT> both / "
                             "destination interface <PORT>"]),
    "CISC-L2-000070": F(low=["! confirm SPAN is available: monitor session <N> / source interface <PORT> both / "
                             "destination interface <PORT>"]),
    "CISC-L2-000090": F(high=each("spanning-tree guard root")),
    "CISC-L2-000100": F(high=["spanning-tree port type edge bpduguard default"]),
    "CISC-L2-000110": F(high=["spanning-tree loopguard default"]),
    "CISC-L2-000120": F(high=each("switchport block unicast")),
    "CISC-L2-000130": F(high=["feature dhcp", "ip dhcp snooping", "ip dhcp snooping vlan <USER_VLANS>",
                              "{each failing section of condition 3}", "  ip dhcp snooping trust",
                              "{each failing section of condition 4}", "  no ip dhcp snooping trust"]),
    "CISC-L2-000140": F(high=each("ip verify source dhcp-snooping-vlan")),
    "CISC-L2-000150": F(high=["ip arp inspection vlan <USER_VLANS>",
                              "{each failing section of condition 2}", "  ip arp inspection trust",
                              "{each failing section of condition 3}", "  no ip arp inspection trust"]),
    "CISC-L2-000160": F(high=each("storm-control broadcast level <STORM_LEVEL_PERCENT>")),
    "CISC-L2-000170": F(low=["ip igmp snooping"]),
    "CISC-L2-000190": F(high=["feature udld"]),
    "CISC-L2-000210": F(low=each("switchport access vlan <PARKING_VLAN>")),
    "CISC-L2-000220": F(high=each("switchport access vlan <USER_VLAN>")),
    "CISC-L2-000230": F(high=each("switchport trunk allowed vlan remove 1")),
    "CISC-L2-000240": F(high=["! move management to a dedicated VLAN first, then:",
                              "interface Vlan1", "  no ip address", "  shutdown"]),
    "CISC-L2-000260": F(high=each("switchport trunk native vlan <NATIVE_VLAN>")),
    # ---- RTR
    "CISC-RT-000020": F(high=["! configure authentication for every routing protocol, e.g. OSPF:",
                              "interface <ROUTING_INTERFACE>", "  ip ospf authentication key-chain <KEY_CHAIN>",
                              "! BGP: router bgp <ASN> / neighbor <PEER> / password 3 <KEY>"]),
    "CISC-RT-000030": F(high=["! set accept-lifetime / send-lifetime of 180 days or less on every key in the key chains"]),
    "CISC-RT-000040": F(high=["interface <ROUTING_INTERFACE>", "  ip ospf authentication message-digest",
                              "  ip ospf message-digest-key 1 md5 3 <KEY>"]),
    "CISC-RT-000050": F(high=["key chain <KEY_CHAIN>", "  key 1", "    key-string <ROUTING_KEY>",
                              "    cryptographic-algorithm hmac-sha-256",
                              "interface <ROUTING_INTERFACE>", "  ip ospf authentication key-chain <KEY_CHAIN>"]),
    "CISC-RT-000060": F(high=["! shut down routed interfaces that are not in use:",
                              "interface <UNUSED_INTERFACE>", "  shutdown"]),
    "CISC-RT-000080": F(high=["! disable Smart Call Home: callhome / no enable (confirm syntax for the release)"]),
    "CISC-RT-000120": F(high=["copp profile strict"]),
    "CISC-RT-000140": F(high=["! in the external and internal ACLs, before any ICMP permit:",
                              "ip access-list <ACL>", "  <SEQ> deny icmp any <DEVICE_ADDRESS>/32 fragments log"]),
    "CISC-RT-000150": F(high=each("no ip arp gratuitous request")),
    "CISC-RT-000160": F(low=each("no ip directed-broadcast")),
    "CISC-RT-000170": F(low=each("no ip unreachables")),
    "CISC-RT-000190": F(low=each("no ip redirects")),
    "CISC-RT-000200": F(high=each("! add 'log' to every deny statement in this ACL")),
    "CISC-RT-000236": F(low=["! on every IPv6 interface:", "interface <IPV6_INTERFACE>", "  ipv6 nd hop-limit 64"]),
    "CISC-RT-000237": F(high=["! replace any FEC0::/10 (site-local) IPv6 addresses"]),
    "CISC-RT-000350": F(low=["no ip source-route"]),
    "CISC-RT-000360": F(high=["no feature lldp"]),
    "CISC-RT-000370": F(high=["no cdp enable"]),
    "CISC-RT-000380": F(high=each("no ip proxy-arp")),
    "CISC-RT-000470": F(high=["router bgp <ASN>", "  neighbor <EBGP_PEER>", "    no disable-connected-check"]),
    "CISC-RT-000490": F(high=["! build the Bogon prefix list (see check text), then for every eBGP peer:",
                              "router bgp <ASN>", "  neighbor <EBGP_PEER>", "    address-family ipv4 unicast",
                              "      prefix-list <BOGON_PREFIX_LIST> in"]),
    "CISC-RT-000500": F(high=["ip prefix-list <INBOUND_FILTER> seq <SEQ> deny <LOCAL_AS_PREFIX> le 32",
                              "router bgp <ASN>", "  neighbor <EBGP_PEER>", "    address-family ipv4 unicast",
                              "      prefix-list <INBOUND_FILTER> in"]),
    "CISC-RT-000510": F(high=["router bgp <ASN>", "  neighbor <CE_PEER>", "    address-family ipv4 unicast",
                              "      prefix-list <CUSTOMER_PREFIX_LIST> in"]),
    "CISC-RT-000520": F(high=["router bgp <ASN>", "  neighbor <CE_PEER>", "    address-family ipv4 unicast",
                              "      prefix-list <ADVERTISE_PREFIX_LIST> out"]),
    "CISC-RT-000530": F(high=["router bgp <ASN>", "  neighbor <EBGP_PEER>", "    address-family ipv4 unicast",
                              "      prefix-list <FILTER_CORE_PREFIXES> out"]),
    "CISC-RT-000540": F(high=["router bgp <ASN>", "  enforce-first-as"]),
    "CISC-RT-000550": F(high=["ip as-path access-list <AS_PATH_ACL> permit ^<CUSTOMER_AS>$", "router bgp <ASN>",
                              "  neighbor <CE_PEER>", "    address-family ipv4 unicast",
                              "      filter-list <AS_PATH_ACL> in"]),
    "CISC-RT-000560": F(high=["router bgp <ASN>", "  neighbor <EBGP_PEER>", "    address-family ipv4 unicast",
                              "      maximum-prefix <MAX_PREFIXES>"]),
    "CISC-RT-000570": F(high=["ip prefix-list FILTER_PREFIX_LENGTH seq 5 permit 0.0.0.0/0 ge 8 le 24",
                              "ip prefix-list FILTER_PREFIX_LENGTH seq 10 deny 0.0.0.0/0 le 32",
                              "router bgp <ASN>", "  neighbor <EBGP_PEER>", "    address-family ipv4 unicast",
                              "      prefix-list FILTER_PREFIX_LENGTH in"]),
    "CISC-RT-000580": F(high=["router bgp <ASN>", "  neighbor <IBGP_PEER>", "    update-source loopback0"]),
    "CISC-RT-000590": F(high=["mpls ldp configuration", "  router-id loopback0 force"]),
    "CISC-RT-000600": F(high=["router ospf <OSPF_PROCESS>", "  mpls ldp sync"]),
    "CISC-RT-000620": F(high=["no mpls ip propagate-ttl"]),
    "CISC-RT-000710": F(low=["ip igmp snooping"]),
    "CISC-RT-000750": F(low=["no ip source-route"]),
    "CISC-RT-000760": F(high=["! build the QoS policy per the GIG QoS profile, then on each interface:",
                              "interface <INTERFACE>", "  service-policy type qos output <QOS_POLICY>"]),
    "CISC-RT-000770": F(high=["! build the QoS policy per the GIG QoS profile, then on each interface:",
                              "interface <INTERFACE>", "  service-policy type qos output <QOS_POLICY>"]),
    "CISC-RT-000780": F(high=["class-map type qos match-all SCAVENGER", "  match dscp 8",
                              "! add the SCAVENGER class with low bandwidth to <QOS_POLICY>"]),
    "CISC-RT-000800": F(high=each("ip pim neighbor-policy prefix-list <PIM_NEIGHBOR_LIST>")),
    "CISC-RT-000810": F(high=["interface <EDGE_INTERFACE>", "  ip pim border"]),
    "CISC-RT-000820": F(high=["ip pim register-policy <PIM_REGISTER_FILTER>"]),
    "CISC-RT-000830": F(high=["ip pim register-policy <PIM_REGISTER_FILTER>"]),
    "CISC-RT-000840": F(high=each("ip pim jp-policy <PIM_JOIN_FILTER> in")),
    "CISC-RT-000860": F(high=each("ip igmp report-policy <ALLOWED_GROUPS>")),
    "CISC-RT-000870": F(high=each("ip igmp report-policy <ALLOWED_SOURCES>")),
    "CISC-RT-000880": F(high=each("ip igmp state-limit <IGMP_LIMIT>")),
    "CISC-RT-000890": F(high=["ip pim spt-threshold infinity group-list <SPT_GROUPS>"]),
    "CISC-RT-000910": F(high=["ip msdp password <MSDP_PEER> <MSDP_KEY>"]),
    "CISC-RT-000920": F(high=["ip msdp sa-policy <MSDP_PEER> <INBOUND_SA_FILTER> in"]),
    "CISC-RT-000930": F(high=["ip msdp sa-policy <MSDP_PEER> <OUTBOUND_SA_FILTER> out"]),
    "CISC-RT-000940": F(high=["ip msdp sa-limit <MSDP_PEER> <SA_LIMIT>"]),
    "CISC-RT-000950": F(high=["ip msdp peer <MSDP_PEER> connect-source loopback0 remote-as <ASN>"]),
    "CISC-L2-000250": F(high=["{each failing section of condition 1}", "  switchport mode access"],
                        low=["{each failing section of condition 2}",
                             "  ! label this port: description UPLINK - ... / DOWNLINK - ... / ACCESS - ..."]),
}

FIX_LIBRARY = {"IOSXE_SW": FIX_IOSXE, "IOSXE_RTR": FIX_IOSXE, "NXOS": FIX_NXOS}


def starter_fix(platform, rule_ver):
    return dict(FIX_LIBRARY.get(platform, {}).get(rule_ver) or {"low": "", "high": ""})


# ---------------------------------------------------------------- script generation

def _header_for(cond):
    section = cond.get("section", "")
    only = (cond.get("only") or "").strip().lower()
    if "interface" in section:
        role = only[5:].strip().upper() if only.startswith("role:") else ""
        return f"interface <{role + '_' if role else ''}INTERFACE>"
    if cond.get("section_how") == "regex" or not section.strip():
        return "<SECTION>"
    return f"{section.strip()} <{section.strip().split()[-1].upper().replace('-', '_')}>"


def _placeholder_header(rule, condition=None):
    """Header used for {each failing section ...} when there are no assessment results."""
    conds = (rule.get("pass_logic") or {}).get("conditions", [])
    if condition and 0 < condition <= len(conds):
        return _header_for(conds[condition - 1])
    for cond in conds:
        if cond.get("scope") == "every":
            return _header_for(cond)
    return "interface <INTERFACE>"


def render(fix_text, failed_sections, placeholder, by_condition=None, rule=None, have_results=None):
    """Expand {each failing section [of condition N]} blocks. Returns the command lines.

    failed_sections: every failing section; by_condition: {"2": [...]} per condition. With assessment results
    (have_results True) a block whose condition passed is left out; without results a placeholder is written.
    """
    if have_results is None:
        have_results = bool(failed_sections)
    lines, out, i = (fix_text or "").splitlines(), [], 0
    while i < len(lines):
        m = EACH_RE.match(lines[i].strip())
        if m:
            block, i = [], i + 1
            while i < len(lines) and (lines[i][:1] in (" ", "\t") or not lines[i].strip()):
                if lines[i].strip():
                    block.append(lines[i])
                i += 1
            if m.group(1):
                n = int(m.group(1))
                failed = (by_condition or {}).get(str(n), [])
                header = _placeholder_header(rule, n) if rule else placeholder
            else:
                failed, header = failed_sections, placeholder
            if have_results and not failed:
                continue  # that condition passed on this device - nothing to fix
            heads = failed or [header]
            if not failed:
                out.append("! EDIT: repeat this block for every section that needs it")
            for head in heads:
                out.append(head)
                out += block
                out.append("exit")
            continue
        out.append(lines[i])
        i += 1
    return out


def has_fix(rule):
    fix = rule.get("fix") or {}
    return bool((fix.get("low") or "").strip() or (fix.get("high") or "").strip())


def _script(impact, title, items, source):
    """items: [(heading, [command lines])] -> full script text, or None if empty."""
    items = [(h, cmds) for h, cmds in items if any(c.strip() for c in cmds)]
    if not items:
        return None, 0
    body, seen = [], {}
    for heading, cmds in items:
        key = tuple(c.strip() for c in cmds if c.strip())
        if key in seen:  # several controls share one fix (e.g. archive / log config) - write it once
            body += ["!", f"! ---- {heading}", f"! (same fix as {seen[key]} above)"]
            continue
        seen[key] = heading.split(":")[0]
        body += ["!", f"! ---- {heading}"] + cmds
    placeholders = sorted({p for _, cmds in items for c in cmds for p in PLACEHOLDER_RE.findall(c)})
    head = [f"! STIGTOOL hardening script - {IMPACT[impact]}", f"! {title}",
            f"! Generated {store.now()} by {store.current_user()}", f"! Source: {source}",
            f"! Controls: {len(items)}"] + HEADER_WARNING[impact]
    if placeholders:
        head += ["!", "! EDIT BEFORE USE - replace every one of these values:"]
        head += [f"!   {p}" for p in placeholders]
    text = "\n".join(head + ["!", "configure terminal"] + body +
                     ["!", "end", "! Verify the device, then save: copy running-config startup-config", ""])
    return text, len(items)


def _heading(stig_short, control_like):
    return (f"{stig_short} {control_like['vuln_id']} ({control_like['rule_ver']}): "
            f"{control_like['title'][:90]}")


def _write(folder, name, text):
    path = folder / name
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def generate_baseline(group, rules_db, index, include_drafts=True):
    """Two scripts for the group covering every control whose rule has fix commands."""
    items = {"low": [], "high": []}
    for stig_id, control, rule in assess.group_plan(group, rules_db, index):
        if rule is None and include_drafts:
            rule = next((r for r in assess.rules_for_control(rules_db, stig_id, control["vuln_id"])
                         if r.get("state") == "draft" and has_fix(r)), None)
        if not rule or not has_fix(rule):
            continue
        placeholder = _placeholder_header(rule)
        for impact in ("low", "high"):
            cmds = render(rule["fix"].get(impact, ""), [], placeholder, rule=rule, have_results=False)
            if cmds:
                items[impact].append((_heading(index[stig_id]["short"], control), cmds))
    folder = store.paths.output / "hardening" / f"{group['id']}_baseline_{store.stamp()}"
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for impact, suffix in (("low", "LOW_IMPACT"), ("high", "IMPACTFUL")):
        text, n = _script(impact, f"Group {group['id']} - baseline for every device in the group",
                          items[impact], "baseline (every control with fix commands"
                          + (", including draft rules)" if include_drafts else ", active rules only)"))
        if text:
            written.append((_write(folder, f"{group['id']}_{suffix}.txt", text), n))
    return folder, written


def generate_from_run(run, group_id, rules_db):
    """Per-device scripts with only the controls that are Open on that device in the assessment run."""
    results = run["results"][group_id]
    per_device = {h: {"low": [], "high": []} for h in results["devices"]}
    rules_by_id = {r["id"]: r for r in rules_db["rules"]}
    for c in results["controls"].values():
        rule = rules_by_id.get(c["rule_id"])
        if not rule or not has_fix(rule) or assess.is_expected_open(c) or c.get("final") in (
                "not_applicable", "not_a_finding"):
            continue
        for host, r in c["per_device"].items():
            if r["status"] != "open":
                continue
            failed = r.get("failed_sections") or []
            by_cond = r.get("failed_by_condition") or {}
            for impact in ("low", "high"):
                cmds = render(rule["fix"].get(impact, ""), failed, _placeholder_header(rule), by_cond, rule,
                              have_results="failed_by_condition" in r)
                if cmds:
                    per_device[host][impact].append((_heading(c["family"], c), cmds))
    folder = store.paths.output / "hardening" / f"{group_id}_run{run['id']}_{store.stamp()}"
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for host, items in per_device.items():
        for impact, suffix in (("low", "LOW_IMPACT"), ("high", "IMPACTFUL")):
            text, n = _script(impact, f"Device {host} (group {group_id})", items[impact],
                              f"assessment run {run['id']} - only controls Open on this device")
            if text:
                written.append((_write(folder, f"{host}_{suffix}.txt", text), n))
    return folder, written
