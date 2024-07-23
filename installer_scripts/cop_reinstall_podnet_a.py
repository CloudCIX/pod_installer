# COP ReInstall PodNet A Configuration
# stdlib
import ipaddress
import json
import os
import subprocess
# lib
import curses
from primitives import firewall_podnet, net
# local
from interface_utils import read_interface_file
from ports import ports
from sql_utils import get_instanciated_infra, get_instanciated_metadata

SYS_NET_DIR = '/sys/class/net/'


def scan_for_new_iface(excluded_ifaces):
    """
    Scan /sys/class/net/ directory for new network interface.
    Returns an new active interface name.
    """
    all_new_ifaces = [interface for interface in os.listdir(SYS_NET_DIR) if interface not in excluded_ifaces]

    new_active_iface, mac = '', None
    for name in all_new_ifaces:
        state = read_interface_file(name, 'operstate')
        status = read_interface_file(name, 'carrier')
        if state == 'up' and status == '1':
            new_active_iface = name
            mac = read_interface_file(name, 'address')
            break
    return new_active_iface, mac


def build(win):
    config_data = get_instanciated_metadata()['config.json']

    excluded_ifaces = ['lo', 'docker', 'mgmt0']
    # 1 Network setup
    win.addstr(1, 1, '1. Network Setup:', curses.color_pair(2))
    # 1.1 Public Interface Setup
    win.addstr(2, 1, '1.1 Public:', curses.color_pair(2))
    # 1.1.1 Connect Public interface
    public_iflname, public_mac = '', None
    while public_iflname == '':
        ports(win)
        # interact with user to connect new interfaces
        win.addstr(18, 1, 'Please connect the `public0` interface and press ENTER.       ', curses.color_pair(2))
        win.refresh()
        user_input = win.getkey()
        while user_input != '\n':
            user_input = win.getkey()

        public_iflname, public_mac = scan_for_new_iface(excluded_ifaces)
        if public_iflname != '':
            ports(win)
            win.addstr(2, 1, '1.1 Public:CONNECTED', curses.color_pair(4))
            win.addstr(18, 1, f'The `public0`:{public_iflname} interface detected.              ', curses.color_pair(4))
            win.refresh()
            break
        else:
            win.addstr(18, 1, 'The `public0` interface NOT detected. Try again please.....   ', curses.color_pair(3))
            win.refresh()

    # 1.1.2 Configure Public interface
    configured, error = net.build(
        host='localhost',
        identifier=public_iflname,
        ips=[
            f'{config_data["ipv4_link_cpe"]}/{config_data["ipv4_link_subnet"].split("/")[1]}',
            f'{config_data["ipv6_link_cpe"]}/{config_data["ipv6_link_subnet"].split("/")[1]}',
        ],
        mac=public_mac,
        name='public0',
    )
    if configured is False:
        win.addstr(2, 1, '1.1 Public:FAILED', curses.color_pair(3))
        win.addstr(18, 1, f'Error: {error}                                              ', curses.color_pair(3))
        win.refresh()
        return False
    win.addstr(2, 1, '1.1 Public:CONFIGURED', curses.color_pair(4))
    win.refresh()
    excluded_ifaces.append('public0')

    # 1.2 Management Interface Setup
    # Management Interface is already configured by cloud-init's user-data for PodNet B

    # 1.3 OOB Interface
    # 1.3.1 Connect oob interface
    oob_iflname, oob_mac = '', None
    win.addstr(3, 1, '1.3 OOB        :', curses.color_pair(2))
    while oob_iflname == '':
        ports(win)
        # interact with user to connect new interfaces
        win.addstr(18, 1, f'Please connect the `oob0` interface and press ENTER.        ', curses.color_pair(2))
        win.refresh()
        user_input = win.getkey()
        while user_input != '\n':
            user_input = win.getkey()

        oob_iflname, oob_mac = scan_for_new_iface(excluded_ifaces)
        if oob_iflname != '':
            win.addstr(3, 1, '1.3 OOB       :CONNECTED', curses.color_pair(4))
            win.addstr(18, 1, f'The `oob0`:{oob_iflname} interface detected.                ', curses.color_pair(4))
            win.refresh()
            break
        else:
            win.addstr(18, 1, f'The `oob0` interface NOT detected. Try again please.....    ', curses.color_pair(3))
            win.refresh()

    # 1.3.2 Configure oob interface
    # sort ipaddresses
    oob_ip = f'100.64.{config_data["pod_number"]}.254'
    configured, error = net.build(
        host='localhost',
        identifier=oob_iflname,
        ips=[f'{oob_ip}/24'],
        mac=oob_mac,
        name='oob0',
        routes=[{'to': '100.64.0.0/10', 'via': '100.64.0.1'}],
    )
    if configured is False:
        win.addstr(3, 1, '1.2 OOB       :FAILED', curses.color_pair(3))
        win.addstr(18, 1, f'Error: {error}                                              ', curses.color_pair(3))
        win.refresh()
        return False
    win.addstr(3, 1, '1.3 OOB       :CONFIGURED', curses.color_pair(4))
    win.refresh()
    excluded_ifaces.append('oob0')

    # 1.4 Private Interface
    win.addstr(4, 1, '1.4 Private   : N/A', curses.color_pair(2))

    # 1.5 Inter Interface
    win.addstr(5, 1, '1.5 Inter     : N/A', curses.color_pair(2))

    win.addstr(18, 1, f'Please press ENTER to continue Update Config json block.    ', curses.color_pair(2))
    win.refresh()
    user_input = win.getkey()
    while user_input != '\n':
        user_input = win.getkey()
    win.clear()

    # 2 Update Config.json
    win.addstr(1, 1, '2. Update Config json:                          ', curses.color_pair(2))
    win.refresh()
    # 2.1 Update Interface names
    # 2.1.1 Find the logical interface name for Public Interface from netplan data
    # It is already known in Public Interface setup step 1.1.1

    # 2.1.2 Find the logical interface name for Management Interface from netplan data
    mgmt_iflname = ''
    instanciated_infra = get_instanciated_infra()
    ethernets = instanciated_infra['netplan']['network']['ethernets']
    for interface_lname, interface_data in ethernets.items():
        if interface_data.get('set-name', '') == 'mgmt0':
            mgmt_iflname = interface_lname
            break

    # 2.1.2 Create dictionary for interfaces to update config.json with logical names
    logical_ifnames = {
        'podnet_a_public_ifname': public_iflname,
        'podnet_a_mgmt_ifname': mgmt_iflname,
        'podnet_a_oob_ifname': oob_iflname,
    }
    with open('/etc/cloudcix/pod/configs/config.json', 'r') as file:
        config_json = json.load(file)
    updated_config = {key: logical_ifnames.get(key, val) for key, val in config_json.items()}
    with open('/etc/cloudcix/pod/configs/config.json', 'w') as file:
        json.dump(updated_config, file, indent=4)
    win.addstr(1, 1, '2. Update Config json:                   SUCCESS', curses.color_pair(4))

    win.addstr(18, 1, f'Please press ENTER to continue Firewall setup block.        ', curses.color_pair(2))
    win.refresh()
    user_input = win.getkey()
    while user_input != '\n':
        user_input = win.getkey()
    win.clear()

    # 3. Firewall
    win.addstr(1, 1, '3. Firewall Setup:                              ', curses.color_pair(2))
    # 3.1 Prepare Firewall rules
    win.addstr(2, 1, '3.1 Preparing Firewall Rules:                   ', curses.color_pair(2))
    win.refresh()

    # PodNet IPs
    pms_ips = list(ipaddress.IPv4Network(config_data['primary_ipv4_subnet']).hosts())
    mgmt_ipv6_3hex = config_data['ipv6_subnet'].split('/')[0][:-2]

    firewall_rules = [
        # 3.1.1 Inbound IPv4
        # a: "lo" icmp accept
        {'order': 3111, 'version': '4', 'iiface': 'lo', 'oiface': '', 'protocol': 'icmp', 'action': 'accept', 'log': True, 'source': ['127.0.0.1'], 'destination': ['127.0.0.1'], 'port': []},
        # b: "lo" dns accept
        {'order': 3112, 'version': '4', 'iiface': 'lo', 'oiface': '', 'protocol': 'dns', 'action': 'accept', 'log': True, 'source': ['127.0.0.1'], 'destination': ['127.0.0.53'], 'port': []},
        # c: Ping Accept on Public interface
        {'order': 3113, 'version': '4', 'iiface': 'public0', 'oiface': '', 'protocol': 'icmp', 'action': 'accept', 'log': True, 'source': [config_data['ipv4_link_pe']] + [asgn.strip() for asgn in config_data['pat_region_assignments'].split(',')], 'destination': [config_data['ipv4_link_cpe']], 'port': []},
        # d: VPN Accept on Public interface: N/A
        # e: Ping Accept on Management interface
        {'order': 3115, 'version': '4', 'iiface': 'mgmt0', 'oiface': '', 'protocol': 'icmp', 'action': 'accept', 'log': True, 'source': [config_data['primary_ipv4_subnet'], config_data['ipv4_link_pe']] + [asgn.strip() for asgn in config_data['pat_region_assignments'].split(',')], 'destination': [f'{pms_ips[0]}', f'{pms_ips[1]}', config_data['ipv4_link_cpe']], 'port': []},
        # f: Ping Accept on OOB interface IP
        {'order': 3116, 'version': '4', 'iiface': 'oob0', 'oiface': '', 'protocol': 'icmp', 'action': 'accept', 'log': True, 'source': ['192.168.2.0/23'], 'destination': [oob_ip], 'port': []},
        # g: SSH to OOB Interface by PAT
        {'order': 3117, 'version': '4', 'iiface': 'oob0', 'oiface': '', 'protocol': 'tcp', 'action': 'accept', 'log': True, 'source': ['192.168.2.0/23'], 'destination': [oob_ip], 'port': ['22']},
        # Block all IPv4 traffic to Private interface: Since default rules are blocked, no need this.
        # Block all IPv4 traffic to Inter interface: Since default rules are blocked, no need this.

        # 3.1.2 Inbound IPv6
        # h: "lo" icmp accept
        {'order': 3121, 'version': '6', 'iiface': 'lo', 'oiface': '', 'protocol': 'icmp', 'action': 'accept', 'log': True, 'source': ['::/128'], 'destination': ['::/128'], 'port': []},
        # i: Ping Accept on Public interface
        {'order': 3122, 'version': '6', 'iiface': 'public0', 'oiface': '', 'protocol': 'icmp', 'action': 'accept', 'log': True, 'source': [config_data['ipv6_link_pe'], config_data['pat_ipv6_subnet'], 'fe80::/10'], 'destination': [config_data['ipv6_link_cpe'], 'fe80::/10'], 'port': []},
        # j: Ping Accept on Mgmt interface
        {'order': 3123, 'version': '6', 'iiface': 'mgmt0', 'oiface': '', 'protocol': 'icmp', 'action': 'accept', 'log': True, 'source': [config_data['ipv6_link_pe'], config_data['pat_ipv6_subnet'], f'{mgmt_ipv6_3hex}:d0c6::/64', f'{mgmt_ipv6_3hex}::/64', 'fe80::/10'], 'destination': [config_data['ipv6_link_cpe'], f'{mgmt_ipv6_3hex}::10:0:1', f'{mgmt_ipv6_3hex}::10:0:2', 'ff02::/8', 'fe80::/10'], 'port': []},
        # k: SSH to Mgmt Interface by Robot: N/A
        # Block all IPv6 traffic to Private interface: Since default rules are blocked, no need this.
        # Block all IPv6 traffic to Inter interface: Since default rules are blocked, no need this.

        # 3.1.3 Forward IPv4
        # a: PUBLIC to MGMT : Ping Accept
        {'order': 3131, 'version': '4', 'iiface': 'public0', 'oiface': 'mgmt0', 'protocol': 'icmp', 'action': 'accept', 'log': True, 'source': [config_data['ipv4_link_pe']] + [asgn.strip() for asgn in config_data['pat_region_assignments'].split(',')], 'destination': [config_data['primary_ipv4_subnet']], 'port': []},
        # b: PUBLIC to MGMT : COP nginx(pms4) and portal(pms5) 443 Accept
        {'order': 3132, 'version': '4', 'iiface': 'public0', 'oiface': 'mgmt0', 'protocol': 'tcp', 'action': 'accept', 'log': True, 'source': ['any'], 'destination': [f'{pms_ips[3]}', f'{pms_ips[4]}'], 'port': ['443']},
        # c: MGMT to PUBLIC: Outbound Accept all
        {'order': 3133, 'version': '4', 'iiface': 'mgmt0', 'oiface': 'public0', 'protocol': 'any', 'action': 'accept', 'log': True, 'source': [config_data['primary_ipv4_subnet']], 'destination': ['any'], 'port': []},
        # d: PUBLIC to and from SUBNET BRIDGES: N/A
        # PUBLIC to OOB: Inbound Block From Public to OOB: Since default rules are blocked, no need this
        # OOB to PUBLIC: Outbound Block From OOB to Public: Since default rules are blocked, no need this
        # PUBLIC to PRIVATE: N/A
        # PRIVATE to PUBLIC: N/A
        # PUBLIC to INTER: N/A
        # INTER to PUBLIC: N/A

        # 3.1.4 Forward IPv6
        # e: PUBLIC to MGMT: Ping Accept
        {'order': 3141, 'version': '6', 'iiface': 'public0', 'oiface': 'mgmt0', 'protocol': 'icmp', 'action': 'accept', 'log': True, 'source': [config_data['pat_ipv6_subnet'], config_data['ipv6_link_pe']], 'destination': [f'{mgmt_ipv6_3hex}:d0c6::/64', f'{mgmt_ipv6_3hex}::/64'], 'port': []},
        # f: PUBLIC to MGMT: COP nginx and portal 443 Accept
        {'order': 3142, 'version': '6', 'iiface': 'public0', 'oiface': 'mgmt0', 'protocol': 'tcp', 'action': 'accept', 'log': True, 'source': ['any'], 'destination': [f'{mgmt_ipv6_3hex}:d0c6::4004:a', f'{mgmt_ipv6_3hex}:d0c6::4005:a'], 'port': ['443']},
        # g: MGMT to PUBLIC: Outbound Accept all
        {'order': 3143, 'version': '6', 'iiface': 'mgmt0', 'oiface': 'public0', 'protocol': 'any', 'action': 'accept', 'log': True, 'source': [f'{mgmt_ipv6_3hex}:d0c6::/64', f'{mgmt_ipv6_3hex}::/64'], 'destination': ['any'], 'port': []},
        # h: PUBLIC to and from SUBNET BRIDGES: N/A
        # PUBLIC to OOB: Inbound Block From Public to OOB: Since default rules are blocked, no need this
        # OOB to PUBLIC: Outbound Block From OOB to Public: Since default rules are blocked, no need this
        # PUBLIC to PRIVATE: N/A
        # PRIVATE to PUBLIC: N/A
        # PUBLIC to INTER: N/A
        # INTER to PUBLIC: N/A

        # 3.1.5 Outbound IPv4
        # a: Allow all From all Interfaces
        {'order': 3151, 'version': '4', 'iiface': '', 'oiface': 'any', 'protocol': 'any', 'action': 'accept', 'log': True, 'source': ['127.0.0.0/8', config_data['ipv4_link_cpe'], f'{pms_ips[1]}', oob_ip], 'destination': ['any'], 'port': []},

        # 3.1.6 Outbound IPv6
        # b: Allow all From lo Interface
        {'order': 3161, 'version': '6', 'iiface': '', 'oiface': 'any', 'protocol': 'any', 'action': 'accept', 'log': True, 'source': [config_data['ipv6_link_cpe'], f'{mgmt_ipv6_3hex}::10:0:2'], 'destination': ['any'], 'port': []},
    ]
    win.addstr(2, 1, '3.1 Preparing Firewall Rules:            SUCCESS', curses.color_pair(4))

    # 3.2 Apply Firewall rules
    win.addstr(3, 1, '3.2 Configuring Firewall Rules:                 ', curses.color_pair(2))
    win.refresh()
    #  3.2.1 Calling Primitive
    configured, error = firewall_podnet.build(
        firewall_rules=firewall_rules,
        log_setup=None,
    )
    if configured is False:
        win.addstr(3, 1, '3.2 Configuring Firewall Rules:           FAILED', curses.color_pair(3))
        win.addstr(18, 1, f'Error: {error}', curses.color_pair(3))
        win.refresh()
        return False
    win.addstr(3, 1, '3.2 Configuring Firewall Rules:          SUCCESS', curses.color_pair(4))

    win.addstr(18, 1, f'Please press ENTER to continue RoboSOC setup block.         ', curses.color_pair(2))
    win.refresh()
    user_input = win.getkey()
    while user_input != '\n':
        user_input = win.getkey()
    win.clear()

    # 4. RoboSOC
    win.addstr(1, 1, '4. RoboSOC Setup:                               ', curses.color_pair(2))
    # 4.1 Robosoc cron job
    win.addstr(2, 1, '4.1 RoboSOC Cron job setup:                     ', curses.color_pair(2))
    win.refresh()
    with open('/etc/cron.d/robosoc', 'w') as file:
        file.write('*/15 * * * * root /etc/cloudcix/pod/pod_installer/robosoc.py > /dev/null 2>&1 \n')
    # for cron job file, file must be executable so set to +x
    try:
        subprocess.run(
            'sudo chmod +x /etc/cron.d/robosoc > /dev/null 2>&1',
            shell=True,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        win.addstr(2, 1, '4.1 RoboSOC Cron job setup:               FAILED', curses.color_pair(3))
        win.addstr(18, 1, f'Error: {error}', curses.color_pair(3))
        win.refresh()
    win.addstr(2, 1, '4.1 RoboSOC Cron job setup:              SUCCESS', curses.color_pair(4))
    win.refresh()

    # 5 Docker setup
    # Not Applicable for PodNet B

    # Finish
    return True
