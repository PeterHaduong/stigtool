"""Starter DRAFT rules for the Cisco IOS-XE (Switch / Router) and NX-OS STIGs.

These are a starting point written from each control's check text and from how the target platforms
print their configuration:
  IOS-XE Switch STIGs -> Catalyst 9300 (IOS-XE 17.x)
  IOS-XE Router STIGs -> Catalyst 8300 (IOS-XE 17.x)
  NX-OS Switch STIGs  -> Nexus 9336C-FX2 / 93180YC-FX3 (NX-OS 9.3 / 10.x)

Every rule is created as a DRAFT. Before it can be made Active, an admin must review it against the
check text, save a passing and a failing test sample, and adjust anything site-specific (parking VLAN,
approved software releases, which interfaces are external...). Controls that need documents, design
plans or interviews get no rule; they are listed in the report with the reason.

Entries are keyed "<platform>:<rule version>" (platform = IOSXE_SW, IOSXE_RTR, NXOS) with a fallback to
"IOSXE:<rule version>" for IOS-XE checks that are the same on switches and routers.
"""
import re

import assess
import harden
import rules as engine
import store

RUN = "show running-config"
STARTER_NOTE = ("STARTER DRAFT generated from the STIG check text for {platform}. Review it against the check "
                "text, save at least one passing and one failing test sample from a real device, then activate.")
PLATFORM_LABEL = {"IOSXE_SW": "Catalyst 9300 (IOS-XE 17.x)", "IOSXE_RTR": "Catalyst 8300 (IOS-XE 17.x)",
                  "NXOS": "Nexus 9300-series (NX-OS 9.3/10.x)"}


# ---------------------------------------------------------------- condition helpers

def c(check, text, how="starts with", cmd=RUN, scope="all", section="", section_how="starts with", only="",
      exclude="", if_none="fail", op=">=", value="", ignore_case=False):
    return {"command": cmd, "scope": scope, "section": section, "section_how": section_how, "only": only,
            "exclude": exclude, "if_none": if_none, "check": check, "text": text, "how": how,
            "ignore_case": ignore_case, "op": op, "value": str(value)}


def has(text, how="starts with", **kw):
    return c("has", text, how, **kw)


def lacks(text, how="starts with", **kw):
    return c("lacks", text, how, **kw)


def rx_has(pattern, **kw):
    return c("has", pattern, "regex", **kw)


def rx_lacks(pattern, **kw):
    return c("lacks", pattern, "regex", **kw)


def num(text, op, value, how="starts with", **kw):
    return c("number", text, how, op=op, value=value, **kw)


def count(text, op, value, how="starts with", **kw):
    return c("count", text, how, op=op, value=value, **kw)


def every(section, cond, only="", exclude="", if_none="pass", section_how="starts with"):
    """Apply cond to EVERY matching section (no matching sections = pass unless told otherwise)."""
    return {**cond, "scope": "every", "section": section, "section_how": section_how, "only": only,
            "exclude": exclude, "if_none": if_none}


def anysec(section, cond, only="", exclude="", if_none="fail", section_how="starts with"):
    return {**cond, "scope": "any", "section": section, "section_how": section_how, "only": only,
            "exclude": exclude, "if_none": if_none}


def R(*conds, mode="ALL", na=None, note="", cmds=None):
    return {"conds": list(conds), "mode": mode, "na": list(na or []), "note": note, "cmds": cmds}


def MANUAL(reason):
    return {"manual": reason}


# Section shortcuts
VTY = "line vty"
ACTIVE_VTY = dict(exclude="transport input none")
ACCESS = dict(only="switchport mode access", exclude="shutdown")            # IOS-XE access ports
TRUNK = dict(only="switchport mode trunk", exclude="shutdown")
L3IF = dict(only="ip address", exclude="shutdown")                          # IOS-XE / NX-OS routed ports
NX_ACCESS = dict(only="switchport access vlan", exclude="re:^\\s*(shutdown|switchport mode trunk)\\s*$")
DENY_NO_LOG = r"^\s*(\d+\s+)?deny\b(?!.*\blog(-input)?\b)"
DENY_NO_LOGINPUT = r"^\s*(\d+\s+)?deny\b(?!.*\blog-input\b)"
ARCHIVE_LOG = anysec("archive", has("logging enable"))
VLAN1_IN_LIST = r"switchport trunk allowed vlan (add )?(.*,)?1(-\d+)?(,.*)?\s*$"
# Front-panel switch ports only (skips Vlan, Loopback, Port-channel and the Catalyst 9300 AppGigabitEthernet
# app-hosting port, which is a trunk by default).
IOS_PORT = r"^interface (?!AppGig)\S*(Ethernet|GigE)\d"
# Host-facing ports: front-panel ports that are not trunks, routed, management, port-channel members or shut down.
# (Unconfigured Catalyst ports default to 'dynamic auto' and are host ports too.)
IOS_HOST = dict(section_how="regex",
                exclude="re:^\\s*(shutdown|switchport mode trunk|no switchport|vrf forwarding|channel-group)\\b")
# Nexus: unconfigured Ethernet ports are shut down by default, so host ports are the ones with 'no shutdown'.
NX_PORT = r"^interface Ethernet\d"
NX_HOST = dict(section_how="regex", only="re:^\\s*no shutdown\\s*$",
               exclude="re:^\\s*(switchport mode (trunk|fex-fabric)|no switchport|channel-group)\\b")
NX_L3IF = dict(only="ip address", exclude="re:^\\s*(shutdown|vrf member management)\\s*$")
# Port roles come from interface descriptions (team setting, tab 3): "description UPLINK - ...",
# "description DOWNLINK - ...", "description ACCESS - ..." / "UNTRUSTED - ...". Access checks FAIL when no
# access-role ports are found, so unlabelled ports cannot slip past; for core / distribution groups without
# access ports, pick a different rule version or mark the control N/A for that group.
ROLE_ACCESS = dict(only="role:access", exclude="re:^\\s*shutdown\\s*$", if_none="fail")
ROLE_UPLINK = dict(only="role:uplink", exclude="re:^\\s*shutdown\\s*$", if_none="fail")
ROLE_DOWNLINK = dict(only="role:downlink", exclude="re:^\\s*shutdown\\s*$", if_none="pass")
NOT_UPLINK = dict(exclude="role:uplink", if_none="pass")
ROLE_NOTE = ("Uses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks "
             "'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports "
             "'description ACCESS - ...' or 'UNTRUSTED - ...'. ")
LIVE_IOS_PORT = "re:^\\s*(shutdown|no switchport|vrf forwarding|channel-group)\\b"

# Not-applicable shortcuts (the feature is not configured on the device)
NA_BGP = [lacks("router bgp")]
NA_ROUTING = [rx_lacks(r"^router (ospf|ospfv3|bgp|eigrp|isis|rip)\b")]
NA_IOS_MPLS = [rx_lacks(r"^\s*mpls (ip|label protocol|ldp)\b")]
NA_IOS_TE = [lacks("mpls traffic-eng tunnels")]
NA_IOS_VPLS = [rx_lacks(r"^(l2 vfi|l2vpn vfi|bridge-domain)\b")]
NA_IOS_PIM = [lacks("ip multicast-routing")]
NA_MSDP = [lacks("ip msdp peer")]
NA_IPV6 = [rx_lacks(r"^\s*ipv6 address\b")]
NA_PERSIST = [lacks("logging persistent")]
NA_IOS_PKI = [lacks("crypto pki trustpoint")]
NA_AUX = [lacks("line aux")]
NA_SNMP = [rx_lacks(r"^snmp-server (group|user|host|community)\b")]
NA_NX_BGP = [lacks("feature bgp")]
NA_NX_ROUTING = [rx_lacks(r"^feature (ospf|ospfv3|bgp|eigrp|isis|rip)\b")]
NA_NX_MPLS = [rx_lacks(r"^(feature mpls|install feature-set mpls|feature-set mpls)\b")]
NA_NX_PIM = [lacks("feature pim")]
NA_NX_MSDP = [lacks("feature msdp")]
NA_NX_OSPF = [lacks("feature ospf")]

PERIMETER = ("Perimeter / alternate-gateway / OOBM requirement: first identify which interfaces are external, "
             "internal or OOBM and what the approved ACLs are; then build a group-specific rule (e.g. for "
             "border routers only).")
DESIGN = "Must be compared with the network design / implementation plan (VRF, RT/RD, VC ID, VPN ID); no fixed config pattern."
INTERVIEW = "Requires interviewing the ISSM / administrator (e.g. unique keys per AS); keys are not visible in configuration."


# ---------------------------------------------------------------- IOS-XE (Catalyst 9300 / 8300)

IOSXE = {
    "CISC-ND-000010": R(
        every(VTY, has("session-limit"), **ACTIVE_VTY),
        note="Platforms without session-limit pass by limiting active vty lines instead (vty 0 1 transport ssh, "
             "others 'transport input none') - adjust if so. If 'ip http secure-server' is on, also require "
             "'ip http max-connections'."),
    "CISC-ND-000090": R(ARCHIVE_LOG),
    "CISC-ND-000100": R(ARCHIVE_LOG),
    "CISC-ND-000110": R(ARCHIVE_LOG),
    "CISC-ND-000120": R(ARCHIVE_LOG),
    "CISC-ND-000140": R(every(VTY, rx_has(r"^\s*access-class \S+ in"), **ACTIVE_VTY),
                        note="Also confirm the ACL only permits the management network."),
    "CISC-ND-000150": R(num("login block-for", ">=", 900), num("attempts", "<=", 3, how="contains")),
    "CISC-ND-000160": R(has("banner login"),
                        has("You are accessing a U.S. Government (USG) Information System", how="contains")),
    "CISC-ND-000210": R(has("logging userinfo", how="whole line"), ARCHIVE_LOG),
    "CISC-ND-000280": R(has("service timestamps log datetime")),
    "CISC-ND-000290": R(every("ip access-list extended", rx_lacks(DENY_NO_LOGINPUT)),
                        note="Only interface-bound ACLs matter; CoPP / route-filter ACLs may need excluding."),
    "CISC-ND-000330": R(ARCHIVE_LOG),
    "CISC-ND-000380": R(lacks("file privilege"), na=NA_PERSIST),
    "CISC-ND-000390": R(lacks("file privilege"), na=NA_PERSIST),
    "CISC-ND-000460": R(lacks("file privilege"), na=NA_PERSIST),
    "CISC-ND-000470": R(*[lacks(t, how="whole line") for t in (
        "ip boot server", "ip bootp server", "ip dns server", "ip identd", "ip finger", "ip http server",
        "ip rcmd rcp-enable", "ip rcmd rsh-enable", "service config", "service finger", "service tcp-small-servers",
        "service udp-small-servers", "service pad", "service call-home")], lacks("boot network"),
        note="Catalyst 9300/8300 17.x often ship with 'service call-home' and 'ip http server' on. Call-home is "
             "allowed only on legacy devices that need it for Smart Licensing - otherwise a finding."),
    "CISC-ND-000490": R(count("username ", "==", 1),
                        rx_has(r"^aaa authentication login \S+ group \S+ .*\blocal\b"),
                        note="Exactly one local account; local must come after the AAA server group."),
    "CISC-ND-000550": R(anysec("aaa common-criteria policy", num("min-length", ">=", 15))),
    "CISC-ND-000570": R(anysec("aaa common-criteria policy", num("upper-case", ">=", 1))),
    "CISC-ND-000580": R(anysec("aaa common-criteria policy", num("lower-case", ">=", 1))),
    "CISC-ND-000590": R(anysec("aaa common-criteria policy", num("numeric-count", ">=", 1))),
    "CISC-ND-000600": R(anysec("aaa common-criteria policy", num("special-case", ">=", 1))),
    "CISC-ND-000610": R(anysec("aaa common-criteria policy", num("char-changes", ">=", 8))),
    "CISC-ND-000620": R(has("service password-encryption", how="whole line"), has("enable secret"),
                        lacks("enable password")),
    "CISC-ND-000720": R(every(VTY, num("exec-timeout", "<=", 5), **ACTIVE_VTY),
                        every("line con", num("exec-timeout", "<=", 5), if_none="fail"),
                        rx_lacks(r"^\s*exec-timeout 0 0\s*$"),
                        note="exec-timeout absent = default 10 minutes (finding). If 'ip http secure-server' is on, "
                             "also check 'ip http timeout-policy idle 300' or less."),
    "CISC-ND-000880": R(ARCHIVE_LOG),
    "CISC-ND-000980": R(rx_has(r"^logging buffered \d+")),
    "CISC-ND-001000": R(rx_lacks(r"^logging trap (emergencies|alerts|0|1)\s*$"),
                        note="No 'logging trap' line means informational (compliant)."),
    "CISC-ND-001030": R(count("ntp server", ">=", 2)),
    "CISC-ND-001130": R(rx_has(r"^snmp-server group \S+ v3 (auth|priv)\b"), rx_lacks(r"^snmp-server group \S+ v3 noauth\b"),
                        lacks("snmp-server community"),
                        rx_lacks(r"Authentication Protocol:\s*(MD5|None)", cmd="show snmp user"),
                        na=NA_SNMP, cmds=[RUN, "show snmp user"],
                        note="IOS-XE does not print SNMPv3 users in the running-config, so the HMAC is read from "
                             "'show snmp user' (SHA / SHA-2 required)."),
    "CISC-ND-001140": R(rx_has(r"^snmp-server group \S+ v3 priv\b"), rx_lacks(r"^snmp-server group \S+ v3 (auth|noauth)\b"),
                        rx_lacks(r"Privacy Protocol:\s*(None|DES|3DES)\b", cmd="show snmp user"),
                        na=NA_SNMP, cmds=[RUN, "show snmp user"]),
    "CISC-ND-001150": R(has("ntp authenticate", how="whole line"), rx_has(r"^ntp authentication-key \d+ hmac-sha2"),
                        has("ntp trusted-key"), rx_lacks(r"^ntp server (?!.*\bkey\b)"),
                        note="hmac-sha2-256 NTP keys need a recent IOS-XE 17.x release; older releases only offer MD5."),
    "CISC-ND-001200": R(has("ip ssh version 2", how="whole line"), has("ip ssh server algorithm mac"),
                        rx_lacks(r"^ip ssh server algorithm mac .*hmac-sha1")),
    "CISC-ND-001210": R(has("ip ssh server algorithm encryption"),
                        rx_lacks(r"^ip ssh server algorithm encryption .*(cbc|3des)")),
    "CISC-ND-001250": R(ARCHIVE_LOG),
    "CISC-ND-001260": R(has("login on-failure log"), has("login on-success log")),
    "CISC-ND-001270": R(ARCHIVE_LOG),
    "CISC-ND-001370": R(count(r"^(radius server|tacacs server|radius-server host|tacacs-server host) ", ">=", 2, how="regex"),
                        rx_has(r"^aaa authentication login \S+ group ")),
    "CISC-ND-001410": R(anysec("event manager applet", has("CONFIG_I", how="contains")),
                        anysec("event manager applet", rx_has(r"copy running-config (scp|sftp|https)://")),
                        has("file prompt quiet", how="whole line"),
                        note="Also confirm no cleartext password is embedded in the copy URL."),
    "CISC-ND-001440": R(anysec("crypto pki trustpoint", rx_has(r"^\s*enrollment (url|terminal|profile)\b")),
                        rx_lacks(r"^\s*enrollment selfsigned\b"), na=NA_IOS_PKI,
                        note="Reviewer must confirm the CA is DoD / DoD-approved. IOS-XE creates a self-signed "
                             "trustpoint for HTTPS - remove it or replace it with a CA-issued certificate. Cisco's "
                             "SLA-TrustPoint (licensing, 'enrollment pkcs12') is ignored."),
    "CISC-ND-001450": R(count(r"^logging (host \S+|\d+\.\d+\.\d+\.\d+)", ">=", 2, how="regex")),
    "CISC-ND-001470": R(rx_has(r"Cisco IOS XE Software, Version 17\.(0?9|12|15)\.", cmd="show version"),
                        cmds=["show version"],
                        note="EDIT the version list to the Cisco-supported / site-approved releases before use."),
    # ---- RTR (shared by switch and router unless overridden below)
    "CISC-RT-000010": MANUAL("Organization-defined information-flow policy: review the ACL design for each group."),
    "CISC-RT-000050": R(has("key chain"), anysec("key chain", has("cryptographic-algorithm hmac-sha", how="contains")),
                        na=NA_ROUTING,
                        note="Check every routing protocol: OSPF interfaces 'ip ospf authentication key-chain', BGP "
                             "neighbors 'ao <keychain>', key lifetimes 180 days or less. EIGRP/RIP/IS-IS (MD5 only) "
                             "are a permanent finding."),
    "CISC-RT-000060": R(rx_lacks(r"^\S+\s+\d+\.\d+\.\d+\.\d+\s+\S+\s+\S+\s+down\s+down\s*$",
                                 cmd="show ip interface brief"),
                        cmds=["show ip interface brief"],
                        note="Flags interfaces that have an IP address, are not shut down, and are down/down. "
                             "Unaddressed switchports are ignored."),
    "CISC-RT-000090": R(lacks("service config", how="whole line"), lacks("boot network"), lacks("cns ")),
    "CISC-RT-000120": R(has("policy-map system-cpp-policy", how="whole line"),
                        anysec("control-plane", rx_has(r"^\s*service-policy input \S+")), mode="ANY",
                        note="Catalyst 9300 uses the built-in system-cpp-policy; Catalyst 8300 uses a 'control-plane' "
                             "service-policy. Also review policer rates with 'show policy-map control-plane'."),
    "CISC-RT-000150": R(lacks("ip gratuitous-arps", how="whole line")),
    "CISC-RT-000160": R(every("interface", lacks("ip directed-broadcast", how="whole line"))),
    "CISC-RT-000170": R(every("interface", has("no ip unreachables", how="whole line"), **L3IF),
                        note="Applies to EXTERNAL interfaces only - narrow 'only' / 'skip' to your external "
                             "interfaces (or use 'ip icmp rate-limit unreachable' on the DODIN backbone)."),
    "CISC-RT-000180": R(every("interface", lacks("ip mask-reply", how="whole line"))),
    "CISC-RT-000190": R(every("interface", has("no ip redirects", how="whole line"), **L3IF),
                        note="Applies to EXTERNAL interfaces only - narrow to your external interfaces."),
    "CISC-RT-000200": R(every("ip access-list extended", rx_lacks(DENY_NO_LOG))),
    "CISC-RT-000210": R(every("ip access-list extended", rx_lacks(DENY_NO_LOGINPUT))),
    "CISC-RT-000220": R(every("ip access-list extended", rx_lacks(DENY_NO_LOGINPUT))),
    "CISC-RT-000230": R(anysec("line aux", has("no exec", how="whole line")), na=NA_AUX),
    "CISC-RT-000235": R(lacks("no ip cef", how="whole line"), lacks("no ipv6 cef", how="whole line"),
                        note="CEF is on by default and only shows when disabled."),
    "CISC-RT-000236": R(rx_lacks(r"^\s*ipv6 (nd )?hop-limit ([0-9]|[12][0-9]|3[01])\s*$"), na=NA_IPV6),
    "CISC-RT-000237": R(lacks("ipv6 address fec", how="contains", ignore_case=True), na=NA_IPV6),
    "CISC-RT-000360": R(lacks("lldp run", how="whole line"),
                        note="If LLDP is needed internally, change to: every EXTERNAL interface has 'no lldp transmit'."),
    "CISC-RT-000370": R(lacks("cdp run", how="whole line"), has("no cdp run", how="whole line"), mode="ANY",
                        note="If CDP is needed internally, change to: every EXTERNAL interface has 'no cdp enable'."),
    "CISC-RT-000380": R(every("interface", has("no ip proxy-arp", how="whole line"), **L3IF),
                        note="Proxy ARP is on by default. Applies to EXTERNAL interfaces - narrow as needed."),
    "CISC-RT-000470": R(anysec("router bgp", has("ttl-security hops", how="contains")), na=NA_BGP,
                        note="Every eBGP neighbor needs ttl-security; refine per neighbor."),
    "CISC-RT-000480": MANUAL(INTERVIEW),
    "CISC-RT-000490": R(rx_has(r"^ip prefix-list \S+ seq \d+ deny 10\.0\.0\.0/8"),
                        anysec("router bgp", rx_has(r"neighbor \S+ (prefix-list|route-map) \S+ in\s*$")), na=NA_BGP,
                        note="Confirm the full current Bogon list and that it is applied to ALL external peers."),
    "CISC-RT-000500": R(anysec("router bgp", rx_has(r"neighbor \S+ (prefix-list|route-map) \S+ in\s*$")), na=NA_BGP,
                        note="Reviewer must confirm the inbound filter denies the local AS prefixes."),
    "CISC-RT-000510": R(anysec("router bgp", rx_has(r"neighbor \S+ prefix-list \S+ in\s*$")), na=NA_BGP,
                        note="Only for CE peers; confirm each customer's list holds only its prefixes."),
    "CISC-RT-000520": R(anysec("router bgp", rx_has(r"neighbor \S+ prefix-list \S+ out\s*$")), na=NA_BGP),
    "CISC-RT-000530": R(anysec("router bgp", rx_has(r"neighbor \S+ prefix-list \S+ out\s*$")), na=NA_BGP),
    "CISC-RT-000540": R(lacks("no bgp enforce-first-as", how="contains"), na=NA_BGP),
    "CISC-RT-000550": R(has("ip as-path access-list"), anysec("router bgp", rx_has(r"neighbor \S+ filter-list \S+ in")),
                        na=NA_BGP),
    "CISC-RT-000560": R(anysec("router bgp", has("maximum-prefix", how="contains")), na=NA_BGP),
    "CISC-RT-000570": R(rx_has(r"^ip prefix-list \S+ .*le 24\b"),
                        anysec("router bgp", rx_has(r"neighbor \S+ prefix-list \S+ in\s*$")), na=NA_BGP),
    "CISC-RT-000580": R(anysec("router bgp", rx_has(r"neighbor \S+ update-source [Ll]oopback")), na=NA_BGP),
    "CISC-RT-000590": R(lacks("mpls ldp router-id"), rx_has(r"^mpls ldp router-id [Ll]oopback"), mode="ANY",
                        na=NA_IOS_MPLS),
    "CISC-RT-000600": R(anysec(r"^router (ospf|isis)\b", has("mpls ldp sync"), section_how="regex"), na=NA_IOS_MPLS),
    "CISC-RT-000610": R(has("ip rsvp signalling rate-limit"), na=NA_IOS_TE),
    "CISC-RT-000620": R(has("no mpls ip propagate-ttl"), na=NA_IOS_MPLS),
    "CISC-RT-000630": MANUAL(DESIGN),
    "CISC-RT-000640": MANUAL(DESIGN),
    "CISC-RT-000650": MANUAL(DESIGN),
    "CISC-RT-000660": MANUAL("Permanent finding per the STIG (no FIPS MAC for targeted LDP); CAT III if MD5 "
                             "'mpls ldp neighbor ... password' is configured - review and document."),
    "CISC-RT-000670": MANUAL(DESIGN),
    "CISC-RT-000680": MANUAL(DESIGN),
    "CISC-RT-000690": R(lacks("no-split-horizon", how="contains"), na=NA_IOS_VPLS),
    "CISC-RT-000700": R(every("interface", has("storm-control broadcast", how="contains"), only="re:^\\s*bridge-domain"),
                        na=NA_IOS_VPLS),
    "CISC-RT-000710": R(lacks("no ip igmp snooping", how="contains"), na=NA_IOS_VPLS),
    "CISC-RT-000720": R(every("bridge-domain", has("mac limit maximum addresses", how="contains")), na=NA_IOS_VPLS),
    "CISC-RT-000730": MANUAL("Needs the IP core address space to verify the CE-facing ACL blocks it."),
    "CISC-RT-000740": MANUAL("Needs the list of CE-facing interfaces ('ip verify unicast source reachable-via any')."),
    "CISC-RT-000750": R(rx_has(r"^ip options (drop|ignore)\b"), na=NA_IOS_MPLS),
    "CISC-RT-000760": R(has("policy-map"), rx_has(r"^\s*service-policy output \S+"), na=NA_IOS_MPLS,
                        note="Confirm the classes / bandwidth match the GIG QoS technical profile."),
    "CISC-RT-000770": R(has("policy-map"), rx_has(r"^\s*service-policy output \S+"), na=NA_IOS_MPLS,
                        note="Confirm the classes / bandwidth match the GIG QoS technical profile."),
    "CISC-RT-000780": R(rx_has(r"match (ip )?dscp (cs1|8)\b"), rx_has(r"^\s*service-policy (output|input) \S+"),
                        note="Scavenger (CS1) class with low priority in the QoS policy."),
    "CISC-RT-000790": MANUAL("Compare PIM-enabled interfaces with the multicast topology diagram."),
    "CISC-RT-000800": R(every("interface", has("ip pim neighbor-filter"), only="re:^\\s*ip pim (sparse|dense)"),
                        na=NA_IOS_PIM),
    "CISC-RT-000810": R(anysec("interface", has("ip multicast boundary")), na=NA_IOS_PIM,
                        note="Edge multicast routers only."),
    "CISC-RT-000820": R(has("ip pim accept-register"), has("ip pim register-rate-limit"), na=NA_IOS_PIM,
                        note="Rendezvous Point routers only; also verify MSDP peer filtering."),
    "CISC-RT-000830": R(has("ip pim accept-register"), na=NA_IOS_PIM, note="Rendezvous Point routers only."),
    "CISC-RT-000840": R(has("ip pim accept-rp"), na=NA_IOS_PIM, note="Rendezvous Point routers only."),
    "CISC-RT-000850": R(has("ip pim register-rate-limit"), na=NA_IOS_PIM, note="Rendezvous Point routers only."),
    "CISC-RT-000860": R(every("interface", has("ip igmp access-group"), only="re:^\\s*ip pim (sparse|dense)"),
                        na=NA_IOS_PIM, note="Source Specific Multicast only; N/A for Any Source Multicast."),
    "CISC-RT-000870": R(every("interface", has("ip igmp access-group"), only="re:^\\s*ip pim (sparse|dense)"),
                        na=NA_IOS_PIM, note="Source Specific Multicast only."),
    "CISC-RT-000880": R(has("ip igmp limit"), anysec("interface", has("ip igmp limit")), mode="ANY", na=NA_IOS_PIM),
    "CISC-RT-000890": R(has("ip pim spt-threshold infinity"), na=NA_IOS_PIM),
    "CISC-RT-000900": MANUAL("Review the MSDP-peering interface ACLs (TCP 639) for known peers only."),
    "CISC-RT-000910": R(has("ip msdp password peer"), na=NA_MSDP),
    "CISC-RT-000920": R(rx_has(r"^ip msdp sa-filter in "), na=NA_MSDP),
    "CISC-RT-000930": R(rx_has(r"^ip msdp sa-filter out "), na=NA_MSDP),
    "CISC-RT-000940": R(has("ip msdp sa-limit"), na=NA_MSDP),
    "CISC-RT-000950": R(rx_has(r"^ip msdp peer \S+ connect-source [Ll]oopback"), na=NA_MSDP),
    **{f"CISC-RT-000{n}": MANUAL(PERIMETER) for n in (
        "240", "250", "260", "270", "280", "290", "300", "310", "320", "330", "340", "350", "390", "391", "392",
        "393", "394", "395", "396", "397", "398", "400", "410", "420", "430", "440", "450", "460")},
    # ---- L2S (Catalyst 9300)
    "CISC-L2-000020": R(every("interface", rx_has(r"^\s*(authentication port-control auto|access-session port-control "
                                                    r"auto|dot1x pae authenticator|mab)\b"), **ROLE_ACCESS),
                        has("dot1x system-auth-control", how="whole line"),
                        note=ROLE_NOTE + "Every access port needs 802.1x / MAB (legacy 'authentication port-control' "
                             "or IBNS 2.0 'access-session'). Ports in telecom rooms / wiring closets are exempt - "
                             "label them differently."),
    "CISC-L2-000030": R(rx_has(r"VTP Operating Mode\s*:\s*Off", cmd="show vtp status"),
                        rx_has(r"VTP Password:\s*\S+", cmd="show vtp password"), mode="ANY",
                        cmds=["show vtp status", "show vtp password"],
                        note="Catalyst 9300 defaults to VTP Server mode, so a password is required unless VTP is off."),
    "CISC-L2-000040": R(has("policy-map"), rx_has(r"^\s*service-policy (output|input) \S+"),
                        note="Confirm the classes / bandwidth match the QoS policy."),
    "CISC-L2-000090": R(every("interface", has("spanning-tree guard root"), **ROLE_DOWNLINK),
                        note=ROLE_NOTE + "Root Guard on every DOWNLINK (ports facing access-layer switches). "
                             "Access switches with no downlinks pass."),
    "CISC-L2-000100": R(rx_has(r"^spanning-tree portfast (edge )?bpduguard default"),
                        every("interface", has("spanning-tree bpduguard enable"), **ROLE_ACCESS), mode="ANY",
                        note=ROLE_NOTE + "Global portfast bpduguard default, or BPDU Guard on every access port."),
    "CISC-L2-000110": R(has("spanning-tree loopguard default")),
    "CISC-L2-000120": R(every("interface", has("switchport block unicast"), **ROLE_ACCESS), note=ROLE_NOTE),
    "CISC-L2-000130": R(has("ip dhcp snooping", how="whole line"), rx_has(r"^ip dhcp snooping vlan \S+"),
                        every("interface", has("ip dhcp snooping trust", how="whole line"), **ROLE_UPLINK),
                        every("interface", lacks("ip dhcp snooping trust", how="whole line"), **NOT_UPLINK),
                        note=ROLE_NOTE + "Snooping on all user VLANs; 'ip dhcp snooping trust' on every UPLINK and on "
                             "nothing else (trust on a client port lets a rogue DHCP server through)."),
    "CISC-L2-000140": R(every("interface", has("ip verify source"), **ROLE_ACCESS),
                        note=ROLE_NOTE + "802.1x / MAB ports may be exempt - adjust if so."),
    "CISC-L2-000150": R(rx_has(r"^ip arp inspection vlan \S+"),
                        every("interface", has("ip arp inspection trust", how="whole line"), **ROLE_UPLINK),
                        every("interface", lacks("ip arp inspection trust", how="whole line"), **NOT_UPLINK),
                        note=ROLE_NOTE + "DAI on all user VLANs; 'ip arp inspection trust' on every UPLINK and on "
                             "nothing else."),
    "CISC-L2-000160": R(every("interface", has("storm-control broadcast"), **ROLE_ACCESS), note=ROLE_NOTE),
    "CISC-L2-000170": R(lacks("no ip igmp snooping", how="contains")),
    "CISC-L2-000180": R(rx_has(r"^spanning-tree mode (rapid-pvst|mst)\b")),
    "CISC-L2-000190": R(rx_has(r"^udld (enable|aggressive)\b"), anysec("interface", has("udld port")), mode="ANY",
                        note="Only required where there are fiber links to neighbors."),
    "CISC-L2-000200": R(rx_lacks(r"Negotiation of Trunking:\s*On", cmd="show interfaces switchport"),
                        cmds=["show interfaces switchport"],
                        note="Catalyst 9300 ports default to 'dynamic auto' (not shown in the config), so this reads "
                             "'show interfaces switchport'. AppGigabitEthernet ports may need excluding."),
    "CISC-L2-000210": R(every(IOS_PORT, rx_has(r"^\s*switchport access vlan \d+"),
                              only="re:^\\s*shutdown\\s*$", exclude="re:^\\s*(no switchport|vrf forwarding)\\b",
                              section_how="regex"),
                        note="EDIT to your parking VLAN, e.g. text 'switchport access vlan 999' (whole line). Also "
                             "confirm that VLAN is pruned from every trunk."),
    "CISC-L2-000220": R(rx_lacks(r"^1\s+default\s+active\s+\S+", cmd="show vlan brief"), cmds=["show vlan brief"],
                        note="Fails if any port is listed under VLAN 1."),
    "CISC-L2-000230": R(every(IOS_PORT, has("switchport trunk allowed vlan"), section_how="regex", **TRUNK),
                        every(IOS_PORT, rx_lacks(VLAN1_IN_LIST), section_how="regex", **TRUNK)),
    "CISC-L2-000240": R(every("interface Vlan1", rx_lacks(r"^\s*ip address \d"), section_how="whole line")),
    "CISC-L2-000250": R(every("interface", has("switchport mode access", how="whole line"), **ROLE_ACCESS),
                        every(IOS_PORT, has("role:any"), section_how="regex", exclude=LIVE_IOS_PORT),
                        note=ROLE_NOTE + "Condition 1: every access-role port is a static access port. Condition 2: "
                             "every live front-panel port carries a role label, so no port escapes the role-based "
                             "checks."),
    "CISC-L2-000260": R(every(IOS_PORT, rx_has(r"^\s*switchport trunk native vlan ([2-9]|\d{2,})\s*$"),
                              section_how="regex", **TRUNK),
                        note="Alternative: 'vlan dot1q tag native' globally - add as an ANY option if used."),
    "CISC-L2-000270": MANUAL("Needs the native VLAN ID per trunk to compare with access-port VLANs."),
}

# Router (Catalyst 8300) differences
IOSXE_RTR = {
    "CISC-RT-000370": R(lacks("cdp run", how="whole line"), has("no cdp run", how="whole line"), mode="ANY",
                        note="CDP is off by default on IOS-XE routers ('cdp run' appears only when enabled)."),
}
# Switch (Catalyst 9300) differences
IOSXE_SW = {
    "CISC-RT-000370": R(has("no cdp run", how="whole line"),
                        note="CDP is ON by default on Catalyst 9300 and only 'no cdp run' shows when disabled. If CDP "
                             "is needed internally, change to: every EXTERNAL interface has 'no cdp enable'."),
}


# ---------------------------------------------------------------- NX-OS (Nexus 9336C-FX2 / 93180YC-FX3)

NX_ACCT = R(rx_has(r"^aaa accounting default group \S+"),
            note="Also confirm the referenced group has reachable AAA servers.")

NXOS = {
    "CISC-ND-000010": R(anysec(VTY, has("session-limit"))),
    "CISC-ND-000090": NX_ACCT, "CISC-ND-000100": NX_ACCT, "CISC-ND-000110": NX_ACCT, "CISC-ND-000120": NX_ACCT,
    "CISC-ND-000210": NX_ACCT, "CISC-ND-000330": NX_ACCT, "CISC-ND-000880": NX_ACCT, "CISC-ND-000940": NX_ACCT,
    "CISC-ND-001240": NX_ACCT, "CISC-ND-001250": NX_ACCT, "CISC-ND-001270": NX_ACCT,
    "CISC-ND-000140": R(anysec(VTY, rx_has(r"^\s*access-class \S+ in")),
                        anysec("interface mgmt0", rx_has(r"^\s*ip access-group \S+ in")), mode="ANY",
                        note="Also confirm the ACL only permits the management network."),
    "CISC-ND-000150": R(rx_lacks(r"^ssh login-attempts ([4-9]|\d{2,})\b"),
                        note="Default is 3 attempts (not shown in the config)."),
    "CISC-ND-000160": R(has("banner motd"),
                        has("You are accessing a U.S. Government (USG) Information System", how="contains")),
    "CISC-ND-000290": R(every("ip access-list", rx_lacks(DENY_NO_LOG)), has("logging ip access-list cache entries")),
    "CISC-ND-000470": R(lacks("feature telnet", how="whole line"),
                        note="Also review: feature wccp, nxapi, imp, dhcp - allowed only when operationally required "
                             "(feature dhcp is needed for DHCP snooping)."),
    "CISC-ND-000490": R(count("username ", "==", 1), lacks("no aaa authentication login default fallback error local")),
    "CISC-ND-000530": R(rx_has(r"^ssh macs .*hmac-sha2"), rx_lacks(r"^ssh macs .*hmac-sha1\b"),
                        note="'ssh macs' is available on NX-OS 10.x; on 9.3 confirm with 'show ssh server'."),
    "CISC-ND-000570": R(lacks("no password strength-check", how="whole line")),
    "CISC-ND-000580": R(lacks("no password strength-check", how="whole line")),
    "CISC-ND-000590": R(lacks("no password strength-check", how="whole line")),
    "CISC-ND-000600": R(lacks("no password strength-check", how="whole line")),
    "CISC-ND-000720": R(anysec("line console", num("exec-timeout", "<=", 5)), anysec(VTY, num("exec-timeout", "<=", 5)),
                        rx_lacks(r"^\s*exec-timeout 0\s*$")),
    "CISC-ND-000980": R(rx_has(r"^logging logfile \S+ \d+ size \d+")),
    "CISC-ND-001000": R(has("logging server"), rx_lacks(r"^logging server \S+ [01](\s|$)")),
    "CISC-ND-001030": R(count("ntp server", ">=", 2)),
    "CISC-ND-001050": MANUAL("UTC is the default and is not shown in the configuration; confirm with 'show clock'."),
    "CISC-ND-001130": R(rx_has(r"^snmp-server user \S+ .*\bauth (sha|sha-\d+)\b"),
                        rx_lacks(r"^snmp-server user \S+ .*\bauth md5\b"), lacks("snmp-server community"), na=NA_SNMP,
                        note="Nexus ships with an 'admin' SNMP user using auth md5 - remove or change it."),
    "CISC-ND-001140": R(rx_has(r"^snmp-server user \S+ .*\bpriv (aes-128|aes)\b"),
                        rx_lacks(r"^snmp-server user \S+ (?!.*\bpriv\b)"), na=NA_SNMP),
    "CISC-ND-001150": MANUAL("Permanent finding per the STIG: NX-OS only supports MD5 for NTP authentication. "
                             "Confirm MD5 authentication is configured as the mitigation and document it."),
    "CISC-ND-001200": R(rx_has(r"^ssh macs .*hmac-sha2"), rx_lacks(r"^ssh macs .*hmac-sha1\b"),
                        note="'ssh macs' is available on NX-OS 10.x; on 9.3 confirm with 'show ssh server'."),
    "CISC-ND-001210": R(rx_has(r"^ssh ciphers "), rx_lacks(r"^ssh ciphers .*(cbc|3des)"),
                        note="'ssh ciphers' is available on NX-OS 10.x; on 9.3 confirm with 'show ssh server'."),
    "CISC-ND-001220": R(rx_has(r"^policy-map type control-plane "),
                        anysec("control-plane", rx_has(r"^\s*service-policy input \S+")),
                        note="Nexus 9000 applies a default CoPP profile (copp-system-p-policy-*); review the rates."),
    "CISC-ND-001260": R(num("logging level authpri", ">=", 6), has("logging logfile")),
    "CISC-ND-001280": R(num("logging level authpri", ">=", 6)),
    "CISC-ND-001310": R(has("logging server")),
    "CISC-ND-001370": R(count(r"^(radius|tacacs)-server host ", ">=", 2, how="regex"),
                        rx_has(r"^aaa authentication login (default|console) group ")),
    "CISC-ND-001410": R(anysec("event manager applet", has("CONFIG_I", how="contains")),
                        anysec("event manager applet", rx_has(r"copy (running|startup)-config (scp|sftp)://"))),
    "CISC-ND-001440": R(anysec("crypto ca trustpoint", has("enrollment")), na=[lacks("crypto ca trustpoint")],
                        note="Reviewer must confirm the CA is DoD / DoD-approved ('show crypto ca certificates')."),
    "CISC-ND-001450": R(count("logging server", ">=", 2)),
    "CISC-ND-001470": R(rx_has(r"NXOS: version (9\.3\(1[0-9]\)|10\.[2-5]\()", cmd="show version"), cmds=["show version"],
                        note="EDIT the version list to the Cisco-supported / site-approved releases before use."),
    # ---- L2S
    "CISC-L2-000020": R(every(NX_PORT, rx_has(r"^\s*dot1x (port-control auto|mac-auth-bypass)"), section_how="regex",
                              **ROLE_ACCESS),
                        has("feature dot1x", how="whole line"),
                        note=ROLE_NOTE + "Data-center leaf ports rarely face users; mark N/A per group if no LAN "
                             "outlets connect."),
    "CISC-L2-000080": R(every(NX_PORT, rx_has(r"^\s*dot1x (port-control auto|mac-auth-bypass)"), section_how="regex",
                              **ROLE_ACCESS),
                        has("feature dot1x", how="whole line"),
                        note=ROLE_NOTE + "Data-center leaf ports rarely face users; mark N/A per group if no LAN "
                             "outlets connect."),
    "CISC-L2-000030": R(lacks("feature vtp", how="whole line"), rx_has(r"^vtp mode (transparent|off)\b"),
                        has("vtp password"), mode="ANY"),
    "CISC-L2-000060": R(rx_has(r"^monitor session \d+"),
                        note="The STIG asks for the CAPABILITY to capture a session; a reviewer may accept NaF "
                             "without a configured session."),
    "CISC-L2-000070": R(rx_has(r"^monitor session \d+"),
                        note="The STIG asks for the CAPABILITY to capture a session; a reviewer may accept NaF "
                             "without a configured session."),
    "CISC-L2-000090": R(every("interface", has("spanning-tree guard root"), **ROLE_DOWNLINK),
                        note=ROLE_NOTE + "Root Guard on every DOWNLINK (ports facing access-layer switches / hosts)."),
    "CISC-L2-000100": R(has("spanning-tree port type edge bpduguard default"),
                        every(NX_PORT, has("spanning-tree bpduguard enable"), section_how="regex", **ROLE_ACCESS),
                        mode="ANY", note=ROLE_NOTE),
    "CISC-L2-000110": R(has("spanning-tree loopguard default")),
    "CISC-L2-000120": R(every(NX_PORT, has("switchport block unicast"), section_how="regex", **ROLE_ACCESS),
                        note=ROLE_NOTE),
    "CISC-L2-000130": R(has("ip dhcp snooping", how="whole line"), rx_has(r"^ip dhcp snooping vlan \S+"),
                        every("interface", has("ip dhcp snooping trust", how="whole line"), **ROLE_UPLINK),
                        every("interface", lacks("ip dhcp snooping trust", how="whole line"), **NOT_UPLINK),
                        note=ROLE_NOTE + "'ip dhcp snooping trust' on every UPLINK and on nothing else."),
    "CISC-L2-000140": R(every(NX_PORT, has("ip verify source dhcp-snooping-vlan"), section_how="regex",
                              **ROLE_ACCESS),
                        note=ROLE_NOTE + "802.1x / MAB ports are exempt."),
    "CISC-L2-000150": R(rx_has(r"^ip arp inspection vlan \S+"),
                        every("interface", has("ip arp inspection trust", how="whole line"), **ROLE_UPLINK),
                        every("interface", lacks("ip arp inspection trust", how="whole line"), **NOT_UPLINK),
                        note=ROLE_NOTE + "'ip arp inspection trust' on every UPLINK and on nothing else."),
    "CISC-L2-000160": R(every(NX_PORT, has("storm-control broadcast"), section_how="regex", **ROLE_ACCESS),
                        note=ROLE_NOTE),
    "CISC-L2-000170": R(lacks("no ip igmp snooping", how="contains")),
    "CISC-L2-000190": R(has("feature udld", how="whole line"), every("interface", rx_lacks(r"^\s*udld disable"))),
    "CISC-L2-000210": R(every("interface", rx_has(r"^\s*switchport access vlan \d+"),
                              only="re:^\\s*shutdown\\s*$", exclude="no switchport"),
                        note="EDIT to your parking VLAN, e.g. 'switchport access vlan 999' (whole line)."),
    "CISC-L2-000220": R(every(NX_PORT, rx_has(r"^\s*switchport access vlan ([2-9]|\d{2,})\s*$"), section_how="regex",
                              **ROLE_ACCESS),
                        note=ROLE_NOTE + "Every access port names a VLAN other than 1 (NX-OS 'show vlan' also lists "
                             "trunks, so the config is read instead)."),
    "CISC-L2-000230": R(every("interface", has("switchport trunk allowed vlan"), **TRUNK),
                        every("interface", rx_lacks(VLAN1_IN_LIST), **TRUNK)),
    "CISC-L2-000240": R(every("interface Vlan1", rx_lacks(r"^\s*ip address \d"), section_how="whole line")),
    "CISC-L2-000250": R(every(NX_PORT, lacks("switchport mode trunk", how="whole line"), section_how="regex",
                              **ROLE_ACCESS),
                        every(NX_PORT, has("role:any"), section_how="regex", only="re:^\\s*no shutdown\\s*$",
                              exclude="re:^\\s*(no switchport|channel-group)\\b"),
                        note=ROLE_NOTE + "Condition 1: no access-role port is a trunk. Condition 2: every live Ethernet "
                             "port carries a role label."),
    "CISC-L2-000260": R(every("interface", rx_has(r"^\s*switchport trunk native vlan ([2-9]|\d{2,})\s*$"), **TRUNK)),
    "CISC-L2-000270": MANUAL("Needs the native VLAN ID per trunk to compare with access-port VLANs."),
    # ---- RTR
    "CISC-RT-000010": MANUAL("Organization-defined information-flow policy: review the ACL design for each group."),
    "CISC-RT-000020": R(every("interface", rx_has(r"^\s*ip ospf authentication"), only="ip router ospf"),
                        every("interface", rx_has(r"^\s*ip authentication (mode|key-chain) eigrp"), only="ip router eigrp"),
                        every("interface", rx_has(r"^\s*isis authentication"), only="ip router isis"),
                        every(r"^\s+neighbor \S+", rx_has(r"^\s*password \d"), section_how="regex",
                              exclude="re:^\\s*inherit peer"),
                        na=NA_NX_ROUTING,
                        note="BGP: every neighbor needs 'password'; templates ('inherit peer') need checking by hand."),
    "CISC-RT-000030": R(every(r"^\s+key \d+", has("accept-lifetime"), section_how="regex"),
                        every(r"^\s+key \d+", has("send-lifetime"), section_how="regex"), na=NA_NX_ROUTING,
                        note="Reviewer must confirm each key's lifetime is 180 days or less."),
    "CISC-RT-000040": R(every("interface", rx_has(r"^\s*ip ospf (message-digest-key|authentication key-chain|"
                                                  r"authentication message-digest)"), only="ip router ospf"),
                        na=NA_NX_ROUTING, note="Check BGP / EIGRP / IS-IS authentication types as well."),
    "CISC-RT-000050": R(anysec("key chain", has("cryptographic-algorithm hmac-sha", how="contains")), na=NA_NX_OSPF,
                        note="Only OSPF supports FIPS 198-1 HMAC on NX-OS; BGP/RIP/EIGRP/IS-IS are a finding."),
    "CISC-RT-000060": R(rx_lacks(r"link-down/admin-up", cmd="show ip interface brief vrf all"),
                        cmds=["show ip interface brief vrf all"],
                        note="Flags routed interfaces that are admin-up but link-down."),
    "CISC-RT-000080": R(every("callhome", lacks("enable", how="whole line"))),
    "CISC-RT-000120": R(rx_has(r"^policy-map type control-plane "),
                        anysec("control-plane", rx_has(r"^\s*service-policy input \S+")),
                        note="Nexus 9000 applies a default CoPP profile (copp-system-p-policy-*); review the rates."),
    "CISC-RT-000140": R(anysec("ip access-list", rx_has(r"deny icmp .*\bfragments\b")),
                        note="Must be on external and internal ACLs, before any ICMP permit."),
    "CISC-RT-000150": R(every("interface", has("no ip arp gratuitous", how="contains"), **NX_L3IF),
                        note="Applies to EXTERNAL interfaces only - narrow as needed."),
    "CISC-RT-000160": R(every("interface", lacks("ip directed-broadcast", how="whole line"))),
    "CISC-RT-000170": R(every("interface", lacks("ip unreachables", how="whole line"))),
    "CISC-RT-000190": R(every("interface", has("no ip redirects", how="whole line"), **NX_L3IF),
                        note="Applies to EXTERNAL interfaces only - narrow as needed."),
    "CISC-RT-000200": R(every("ip access-list", rx_lacks(DENY_NO_LOG))),
    "CISC-RT-000236": R(rx_lacks(r"^\s*ipv6 nd hop-limit ([0-9]|[12][0-9]|3[01])\s*$"), na=NA_IPV6),
    "CISC-RT-000237": R(lacks("ipv6 address fec", how="contains", ignore_case=True), na=NA_IPV6),
    "CISC-RT-000350": R(has("no ip source-route", how="whole line")),
    "CISC-RT-000360": R(lacks("feature lldp", how="whole line"),
                        note="If LLDP is needed internally, change to: every EXTERNAL interface has 'no lldp transmit'."),
    "CISC-RT-000370": R(rx_has(r"^no cdp enable\s*$"),
                        note="CDP is on by default. If needed internally, change to: every EXTERNAL interface has "
                             "'no cdp enable'."),
    "CISC-RT-000380": R(every("interface", lacks("ip proxy-arp", how="whole line"))),
    "CISC-RT-000470": R(lacks("disable-connected-check", how="contains"), na=NA_NX_BGP),
    "CISC-RT-000480": MANUAL(INTERVIEW),
    "CISC-RT-000490": R(rx_has(r"^ip prefix-list \S+ seq \d+ deny 10\.0\.0\.0/8"),
                        rx_has(r"^\s+(prefix-list|route-map) \S+ in\s*$"), na=NA_NX_BGP,
                        note="Confirm the full Bogon list and that it is applied to ALL external peers."),
    "CISC-RT-000500": R(rx_has(r"^\s+(prefix-list|route-map) \S+ in\s*$"), na=NA_NX_BGP,
                        note="Reviewer must confirm the inbound filter denies the local AS prefixes."),
    "CISC-RT-000510": R(rx_has(r"^\s+prefix-list \S+ in\s*$"), na=NA_NX_BGP),
    "CISC-RT-000520": R(rx_has(r"^\s+prefix-list \S+ out\s*$"), na=NA_NX_BGP),
    "CISC-RT-000530": R(rx_has(r"^\s+prefix-list \S+ out\s*$"), na=NA_NX_BGP),
    "CISC-RT-000540": R(lacks("no enforce-first-as", how="contains"), na=NA_NX_BGP),
    "CISC-RT-000550": R(has("ip as-path access-list"), rx_has(r"^\s+filter-list \S+ in\s*$"), na=NA_NX_BGP),
    "CISC-RT-000560": R(rx_has(r"^\s+maximum-prefix \d+"), na=NA_NX_BGP),
    "CISC-RT-000570": R(rx_has(r"^ip prefix-list \S+ .*le 24\b"), rx_has(r"^\s+prefix-list \S+ in\s*$"), na=NA_NX_BGP),
    "CISC-RT-000580": R(rx_has(r"^\s+update-source [Ll]oopback"), na=NA_NX_BGP),
    "CISC-RT-000590": R(every("mpls ldp configuration", rx_lacks(r"^\s+router-id ")),
                        every("mpls ldp configuration", rx_has(r"^\s+router-id [Ll]oopback")), mode="ANY", na=NA_NX_MPLS),
    "CISC-RT-000600": R(anysec(r"^router (ospf|isis)\b", has("mpls ldp sync"), section_how="regex"), na=NA_NX_MPLS),
    "CISC-RT-000610": MANUAL("Check RSVP message pacing on TE-enabled Nexus devices (N/A without 'mpls traffic-eng')."),
    "CISC-RT-000620": R(has("no mpls ip propagate-ttl"), na=NA_NX_MPLS),
    "CISC-RT-000710": R(lacks("no ip igmp snooping", how="contains"), na=NA_NX_MPLS),
    "CISC-RT-000750": R(has("no ip source-route", how="whole line"), na=NA_NX_MPLS),
    "CISC-RT-000760": R(rx_has(r"^\s*service-policy type qos (output|input) \S+"), na=NA_NX_MPLS,
                        note="Confirm the classes / bandwidth match the GIG QoS technical profile."),
    "CISC-RT-000770": R(rx_has(r"^\s*service-policy type qos (output|input) \S+"), na=NA_NX_MPLS,
                        note="Confirm the classes / bandwidth match the GIG QoS technical profile."),
    "CISC-RT-000780": R(rx_has(r"match (ip )?dscp (cs1|8)\b"), rx_has(r"^\s*service-policy type qos (output|input) \S+"),
                        note="Scavenger (CS1) class with low priority in the QoS policy."),
    "CISC-RT-000790": MANUAL("Compare PIM-enabled interfaces with the multicast topology diagram."),
    "CISC-RT-000800": R(every("interface", has("ip pim neighbor-policy"), only="ip pim sparse-mode"), na=NA_NX_PIM),
    "CISC-RT-000810": R(anysec("interface", has("ip pim border")), na=NA_NX_PIM, note="Edge multicast switches only."),
    "CISC-RT-000820": R(has("ip pim register-policy"), na=NA_NX_PIM,
                        note="Rendezvous Point only; also verify MSDP peer filtering."),
    "CISC-RT-000830": R(has("ip pim register-policy"), na=NA_NX_PIM, note="Rendezvous Point only."),
    "CISC-RT-000840": R(every("interface", has("ip pim jp-policy"), only="ip pim sparse-mode"), na=NA_NX_PIM,
                        note="Rendezvous Point only."),
    "CISC-RT-000860": R(every("interface", has("ip igmp report-policy"), only="ip pim sparse-mode"), na=NA_NX_PIM,
                        note="Source Specific Multicast only."),
    "CISC-RT-000870": R(every("interface", has("ip igmp report-policy"), only="ip pim sparse-mode"), na=NA_NX_PIM,
                        note="Source Specific Multicast only."),
    "CISC-RT-000880": R(every("interface", has("ip igmp state-limit"), only="ip pim sparse-mode"), na=NA_NX_PIM),
    "CISC-RT-000890": R(has("ip pim spt-threshold infinity"), na=NA_NX_PIM),
    "CISC-RT-000900": MANUAL("Review the MSDP-peering interface ACLs (TCP 639) for known peers only."),
    "CISC-RT-000910": R(rx_has(r"^ip msdp password "), na=NA_NX_MSDP),
    "CISC-RT-000920": R(rx_has(r"^ip msdp sa-policy \S+ .*\bin\s*$"), na=NA_NX_MSDP),
    "CISC-RT-000930": R(rx_has(r"^ip msdp sa-policy \S+ .*\bout\s*$"), na=NA_NX_MSDP),
    "CISC-RT-000940": R(has("ip msdp sa-limit"), na=NA_NX_MSDP),
    "CISC-RT-000950": R(rx_has(r"^ip msdp peer \S+ connect-source [Ll]oopback"), na=NA_NX_MSDP),
    **{f"CISC-RT-000{n}": MANUAL(DESIGN) for n in ("630", "640", "650", "660", "670", "680", "700", "720")},
    "CISC-RT-000730": MANUAL("Needs the IP core address space to verify the CE-facing ACL blocks it."),
    "CISC-RT-000740": MANUAL("Needs the list of CE-facing interfaces ('ip verify unicast source reachable-via any')."),
    **{f"CISC-RT-000{n}": MANUAL(PERIMETER) for n in (
        "240", "250", "260", "270", "310", "320", "330", "340", "390", "391", "450")},
}

LIBRARY = {"IOSXE_SW": {**IOSXE, **IOSXE_SW}, "IOSXE_RTR": {**IOSXE, **IOSXE_RTR}, "NXOS": NXOS}


# ---------------------------------------------------------------- building rules

def platform_of(stig_id):
    s = stig_id.upper().replace("-", "_")
    if "NX_OS" in s or "NXOS" in s:
        return "NXOS"
    if "IOS_XE" in s:
        return "IOSXE_RTR" if "ROUTER" in s else "IOSXE_SW"
    return None


def spec_for(stig_id, rule_ver):
    platform = platform_of(stig_id)
    return platform, (LIBRARY.get(platform) or {}).get(rule_ver)


def build_rule(spec, platform, stig_id, control):
    conds, na = spec["conds"], spec["na"]
    commands = spec["cmds"] or list(dict.fromkeys(cd["command"] for cd in conds + na))
    for cd in na:
        if cd["command"] not in commands:
            commands.append(cd["command"])
    note = STARTER_NOTE.format(platform=PLATFORM_LABEL[platform]) + (f"\n\n{spec['note']}" if spec["note"] else "")
    return {
        "id": store.new_rule_id(), "stig_id": stig_id, "vuln_id": control["vuln_id"], "name": "Starter draft",
        "state": "draft", "is_default": True, "version": 1, "commands": commands,
        "pass_logic": {"mode": spec["mode"], "conditions": [dict(cd) for cd in conds]},
        "na_enabled": bool(na), "na_logic": {"mode": "ALL", "conditions": [dict(cd) for cd in na]},
        "comment": "", "notes": note, "tests": [], "outcome_text": {}, "expected_open": False,
        "check_hash": control["check_hash"], "created_at": store.now(), "created_by": store.current_user(),
        "origin": "starter-drafts", "history": [], "fix": harden.starter_fix(platform, control["rule_ver"]),
    }


def problems_in_library():
    """Every condition in the library that would not run (bad regex etc.) - used by the tests."""
    out = []
    for platform, lib in LIBRARY.items():
        for ver, spec in lib.items():
            if "manual" in spec:
                continue
            commands = spec["cmds"] or [cd["command"] for cd in spec["conds"] + spec["na"]]
            for cd in spec["conds"] + spec["na"]:
                for err in engine.condition_problems(cd, commands):
                    out.append(f"{platform}:{ver}: {err}")
    return out


REFRESH_KEYS = ("commands", "pass_logic", "na_enabled", "na_logic", "notes", "fix")


def untouched(rule):
    """A starter draft nobody has edited or tested yet - safe to replace with a newer starter version."""
    return (rule.get("origin") == "starter-drafts" and rule.get("state") == "draft" and rule.get("version", 1) == 1
            and not rule.get("history") and not rule.get("tests"))


def create_drafts(index, rules_db, stig_ids=None):
    """Create starter drafts for every control that has no rule yet. Returns a report dict."""
    report = {"created": [], "manual": [], "no_entry": [], "skipped": 0, "fixes_added": 0, "refreshed": 0}
    for stig_id, stig in index.items():
        if stig_ids and stig_id not in stig_ids:
            continue
        for vuln_id in stig["order"]:
            control = stig["controls"][vuln_id]
            existing = assess.rules_for_control(rules_db, stig_id, vuln_id, include_retired=True)
            if existing:
                report["skipped"] += 1
                # starter drafts made before fix commands existed get them now (never overwrites edits)
                platform, spec = spec_for(stig_id, control["rule_ver"])
                fix = harden.starter_fix(platform, control["rule_ver"])
                for r in existing:
                    if r.get("origin") != "starter-drafts":
                        continue
                    if untouched(r) and spec and "manual" not in spec:
                        fresh = build_rule(spec, platform, stig_id, control)
                        if any(fresh[k] != r.get(k) for k in REFRESH_KEYS):
                            store.modify_rule(r["id"], lambda x, f=fresh: x.update({k: f[k] for k in REFRESH_KEYS}))
                            report["refreshed"] += 1
                    elif not harden.has_fix(r) and harden.has_fix({"fix": fix}):
                        store.modify_rule(r["id"], lambda x, f=fix: x.__setitem__("fix", f))
                        report["fixes_added"] += 1
                continue
            platform, spec = spec_for(stig_id, control["rule_ver"])
            row = (stig["short"], vuln_id, control["rule_ver"], control["title"])
            if spec is None:
                report["no_entry"].append(row + ("No starter entry for this platform / rule version.",))
            elif "manual" in spec:
                report["manual"].append(row + (spec["manual"],))
            else:
                store.save_rule(build_rule(spec, platform, stig_id, control), check=False)
                report["created"].append(row)
    return report


def report_text(report):
    lines = [f"Starter drafts created: {len(report['created'])}",
             f"Controls that already had a rule (left alone): {report['skipped']}",
             f"Existing starter drafts given fix commands: {report.get('fixes_added', 0)}",
             f"Unedited starter drafts updated to the latest starter version: {report.get('refreshed', 0)}",
             f"Controls needing a human / design decision (no draft): {len(report['manual'])}",
             f"Controls with no starter entry: {len(report['no_entry'])}", ""]
    if report["manual"]:
        lines.append("NEEDS A HUMAN DECISION (consider 'Manual only' or a group-specific rule):")
        for stig, vid, ver, title, why in report["manual"]:
            lines.append(f"  {stig} {vid} ({ver}) {title[:80]}")
            lines.append(f"      -> {why}")
        lines.append("")
    if report["no_entry"]:
        lines.append("NO STARTER ENTRY:")
        lines += [f"  {stig} {vid} ({ver}) {title[:80]}" for stig, vid, ver, title, _ in report["no_entry"]]
    return "\n".join(lines)
