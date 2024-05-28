# PAT Install PodNet A Configuration
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

    excluded_ifaces = ['lo', 'docker', 'public0']
    # 1 Network setup
    win.addstr(1, 1, '1. Network Setup:', curses.color_pair(2))
    # 1.1 Management Interface Setup
    win.addstr(2, 1, '1.1 Management:', curses.color_pair(2))
    # 1.1.1 Connect Mgmt interface
    mgmt_iflname, mgmt_mac = '', None
    while mgmt_iflname == '':
        ports(win)
        # interact with user to connect new interfaces
        win.addstr(18, 1, 'Please connect the `mgmt0` interface and press ENTER.       ', curses.color_pair(2))
        win.refresh()
        user_input = win.getkey()
        while user_input != '\n':
            user_input = win.getkey()

        mgmt_iflname, mgmt_mac = scan_for_new_iface(excluded_ifaces)
        if mgmt_iflname != '':
            ports(win)
            win.addstr(2, 1, '1.1 Management:CONNECTED', curses.color_pair(4))
            win.addstr(18, 1, f'The `mgmt0`:{mgmt_iflname} interface detected.              ', curses.color_pair(4))
            win.refresh()
            break
        else:
            win.addstr(18, 1, 'The `mgmt0` interface NOT detected. Try again please.....   ', curses.color_pair(3))
            win.refresh()

    # 1.1.2 Configure Mgmt interface
    # sort ipaddresses
    primary_ipv4_subnet_items = config_data['primary_ipv4_subnet'].split('/')
    ipv6_subnet_items = config_data['ipv6_subnet'].split('/')
    mgmt_ipv4 = f'{next(ipaddress.IPv4Network(config_data["primary_ipv4_subnet"]).hosts())}/{primary_ipv4_subnet_items[1]}'
    mgmt_ipv6_1 = f'{ipv6_subnet_items[0]}10:0:1'
    mgmt_ipv6_2 = f'{ipv6_subnet_items[0]}10:0:2'
    mgmt_ipv6_3 = f'{ipv6_subnet_items[0]}10:0:3'
    mgmt_route_to = f'{ipv6_subnet_items[0][:ipv6_subnet_items[0].rfind(":")]}d0c6::/64'
    mgmt_route_via = f'{ipv6_subnet_items[0]}4000:1'

    configured, error = net.build(
        host='localhost',
        identifier=mgmt_iflname,
        ips=[mgmt_ipv4, f'{mgmt_ipv6_2}/64'],
        mac=mgmt_mac,
        name='mgmt0',
        routes=[{'to': mgmt_route_to, 'via': mgmt_route_via}],
    )
    if configured is False:
        win.addstr(2, 1, '1.1 Management:FAILED', curses.color_pair(3))
        win.addstr(18, 1, f'Error: {error}                                              ', curses.color_pair(3))
        win.refresh()
        return False
    win.addstr(2, 1, '1.1 Management:CONFIGURED', curses.color_pair(4))
    win.refresh()
    excluded_ifaces.append('mgmt0')

    # 1.2 OOB Interface
    # 1.2.1 Connect oob interface
    oob_iflname, oob_mac = '', None
    win.addstr(3, 1, '1.2 OOB        :', curses.color_pair(2))
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
            win.addstr(3, 1, '1.2 OOB       :CONNECTED', curses.color_pair(4))
            win.addstr(18, 1, f'The `oob0`:{oob_iflname} interface detected.                ', curses.color_pair(4))
            win.refresh()
            break
        else:
            win.addstr(18, 1, f'The `oob0` interface NOT detected. Try again please.....    ', curses.color_pair(3))
            win.refresh()

    # 1.2.2 Configure oob interface
    # sort ipaddresses
    oob_ip = f'10.0.0.254/16'
    configured, error = net.build(
        host='localhost',
        identifier=oob_iflname,
        ips=[oob_ip],
        mac=oob_mac,
        name='oob0',
        routes=[{'to': '10.0.0.0/8', 'via': '10.0.0.1'}],
    )
    if configured is False:
        win.addstr(3, 1, '1.2 OOB       :FAILED', curses.color_pair(3))
        win.addstr(18, 1, f'Error: {error}                                              ', curses.color_pair(3))
        win.refresh()
        return False
    win.addstr(3, 1, '1.2 OOB       :CONFIGURED', curses.color_pair(4))
    win.refresh()
    excluded_ifaces.append('oob0')

    # 1.3 Private Interface
    # 1.3.1 Configure private interface
    private_iflname, private_mac = '', None
    win.addstr(4, 1, '1.3 Private   :', curses.color_pair(2))
    while private_iflname == '':
        ports(win)
        # interact with user to connect new interfaces
        win.addstr(18, 1, f'Please connect the `private0` interface and press ENTER.    ', curses.color_pair(2))
        win.refresh()
        user_input = win.getkey()
        while user_input != '\n':
            user_input = win.getkey()

        private_iflname, private_mac = scan_for_new_iface(excluded_ifaces)
        if private_iflname != '':
            win.addstr(4, 1, '1.3 Private   :CONNECTED', curses.color_pair(4))
            win.addstr(18, 1, f'The `private0`:{private_iflname} interface detected.              ', curses.color_pair(4))
            win.refresh()
            break
        else:
            win.addstr(18, 1, f'`private0` interface NOT detected. Try again please.....      ', curses.color_pair(3))
            win.refresh()

    # 1.3.2 Configure Private interface
    configured, error = net.build(
        host='localhost',
        identifier=private_iflname,
        ips=None,
        mac=private_mac,
        name='private0',
        routes=None,
    )
    if configured is False:
        win.addstr(4, 1, '1.3 Private   :FAILED', curses.color_pair(3))
        win.addstr(18, 1, f'Error: {error}                                              ', curses.color_pair(3))
        win.refresh()
        return False
    win.addstr(4, 1, '1.3 Private   :CONFIGURED', curses.color_pair(4))
    win.refresh()
    excluded_ifaces.append('private0')

    # 1.4 Inter Interface
    # 1.4.1 Configure inter interface
    inter_iflname, inter_mac = '', None
    win.addstr(5, 1, '1.4 Inter     :', curses.color_pair(2))
    while inter_iflname == '':
        ports(win)
        # interact with user to connect new interfaces
        win.addstr(18, 1, f'Please connect the `inter0` interface and press ENTER.        ', curses.color_pair(2))
        win.refresh()
        user_input = win.getkey()
        while user_input != '\n':
            user_input = win.getkey()

        inter_iflname, inter_mac = scan_for_new_iface(excluded_ifaces)
        if inter_iflname != '':
            win.addstr(5, 1, '1.4 Inter     :CONNECTED', curses.color_pair(4))
            win.addstr(18, 1, f'The `inter0`:{inter_iflname} interface detected.            ', curses.color_pair(4))
            win.refresh()
            break
        else:
            win.addstr(18, 1, f'The `inter0` interface NOT detected. Try again please.....  ', curses.color_pair(3))
            win.refresh()

    # 1.4.2 Configure Inter interface
    configured, error = net.build(
        host='localhost',
        identifier=inter_iflname,
        ips=None,
        mac=inter_mac,
        name='inter0',
        routes=None,
    )
    if configured is False:
        win.addstr(5, 1, '1.4 Inter     :FAILED', curses.color_pair(3))
        win.addstr(18, 1, f'Error: {error}                                              ', curses.color_pair(3))
        win.refresh()
        return False
    win.addstr(5, 1, '1.4 Inter     :CONFIGURED', curses.color_pair(4))

    win.addstr(18, 1, f'Please press ENTER to continue Update Config json block.    ', curses.color_pair(2))
    win.refresh()
    user_input = win.getkey()
    while user_input != '\n':
        user_input = win.getkey()
    win.clear()

    # 2 Update Config.json
    win.addstr(1, 1, '2. Update Config json:                       ', curses.color_pair(2))
    win.refresh()
    # 2.1 Update Interface names
    # 2.1.1 Find the logical interface name for Public Interface from netplan data
    public_iflname = ''
    instanciated_infra = get_instanciated_infra()
    ethernets = instanciated_infra['netplan']['network']['ethernets']
    for interface_lname, interface_data in ethernets.items():
        if interface_data.get('set-name', '') == 'public0':
            public_iflname = interface_lname
            break

    # 2.1.2 Create dictionary for interfaces to update config.json with logical names
    logical_ifnames = {
        'podnet_a_public_ifname': public_iflname,
        'podnet_a_mgmt_ifname': mgmt_iflname,
        'podnet_a_oob_ifname': oob_iflname,
        'podnet_a_private_ifname': private_iflname,
        'podnet_a_inter_ifname': inter_iflname,
    }
    with open('/etc/cloudcix/pod/configs/config.json', 'r') as file:
        config_json = json.load(file)
    updated_config = {key: logical_ifnames.get(key, val) for key, val in config_json.items()}
    with open('/etc/cloudcix/pod/configs/config.json', 'w') as file:
        json.dump(updated_config, file, indent=4)
    win.addstr(1, 1, '2. Update Config json:                   SUCCESS', curses.color_pair(2))

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
    cop_nginxcop_ipv4 = f'{ipaddress.ip_address(primary_ipv4_subnet_items[0]) + 4}'
    cop_portal_ipv4 = f'{ipaddress.ip_address(primary_ipv4_subnet_items[0]) + 5}'
    cop_nginxcop_ipv6 = f'{ipv6_subnet_items[0][:-1]}d0c6::4004:a'
    cop_portal_ipv6 = f'{ipv6_subnet_items[0][:-1]}d0c6::5002:4'
    firewall_rules = [
        # 3.1.1 Inbound IPv4
        # 3.1.1.1 Ping
        {'order': 3111, 'version': '4', 'iiface': 'public0', 'oiface': '', 'protocol': 'icmp', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.1.2 DNS
        {'order': 3112, 'version': '4', 'iiface': 'public0', 'oiface': '', 'protocol': 'dns', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.1.3 SSH to OOB Interface by PAT
        {'order': 3113, 'version': '4', 'iiface': 'oob0', 'oiface': '', 'protocol': 'tcp', 'action': 'accept', 'log': True, 'source': ['192.168.2.0/23'], 'destination': ['any'], 'port': ['22']},
        # 3.1.1.4 VPN on Public interface since it has Region in blend
        {'order': 3114, 'version': '4', 'iiface': 'public0', 'oiface': '', 'protocol': 'vpn', 'action': 'accept', 'log': True, 'source': ['any'], 'destination': ['any'], 'port': []},

        # 3.1.2 Inbound IPv6
        # 3.1.2.1 Ping
        {'order': 3121, 'version': '6', 'iiface': 'public0', 'oiface': '', 'protocol': 'icmp', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.2.2 DNS
        {'order': 3122, 'version': '6', 'iiface': 'public0', 'oiface': '', 'protocol': 'dns', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.2.3 SSH to Mgmt Interface by Robot
        {'order': 3123, 'version': '6', 'iiface': 'mgmt0', 'oiface': '', 'protocol': 'tcp', 'action': 'accept','log': True, 'source': [mgmt_ipv6_1, mgmt_ipv6_2, mgmt_ipv6_3], 'destination': ['any'], 'port': ['22']},

        # 3.1.3 Forward IPv4
        # 3.1.3.1 DNS TCP/UDP port 53 From Public to Mgmt
        {'order': 3131, 'version': '4', 'iiface': 'public0', 'oiface': 'mgmt0', 'protocol': 'dns', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.3.2 DNS TCP/UDP port 53 From Public to Private
        {'order': 3132, 'version': '4', 'iiface': 'public0', 'oiface': 'private0', 'protocol': 'dns', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.3.3 VPN Public to Private since it has Region in blend
        {'order': 3133, 'version': '4', 'iiface': 'public0', 'oiface': 'private0', 'protocol': 'vpn', 'action': 'accept', 'log': True, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.3.4 Mgmt Outbound
        {'order': 3134, 'version': '4', 'iiface': 'mgmt0', 'oiface': 'public0', 'protocol': 'any', 'action': 'accept', 'log': True, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.3.5 Private Outbound
        {'order': 3135, 'version': '4', 'iiface': 'private0', 'oiface': 'public0', 'protocol': 'any', 'action': 'accept', 'log': True, 'source': ['any'], 'destination': ['any'], 'port': []},

        # 3.1.4 Forward IPv6
        # 3.1.4.1 DNS TCP/UDP port 53 From Public to Mgmt
        {'order': 3141, 'version': '6', 'iiface': 'public0', 'oiface': 'mgmt0', 'protocol': 'dns', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.4.2 DNS TCP/UDP port 53 From Public to Private
        {'order': 3142, 'version': '6', 'iiface': 'public0', 'oiface': 'private0', 'protocol': 'dns', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.4.3 Mgmt Outbound
        {'order': 3143, 'version': '6', 'iiface': 'mgmt0', 'oiface': 'public0', 'protocol': 'any', 'action': 'accept', 'log': True, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.4.4 Private Outbound
        {'order': 3144, 'version': '6', 'iiface': 'private0', 'oiface': 'public0', 'protocol': 'any', 'action': 'accept', 'log': True, 'source': ['any'], 'destination': ['any'], 'port': []},

        # 3.1.5 Mgmt Specific Forward IPv4
        # 3.1.5.1 Ping
        {'order': 3151, 'version': '4', 'iiface': 'public0', 'oiface': 'mgmt0', 'protocol': 'icmp', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.5.2 COP nginx and portal 443
        {'order': 3152, 'version': '4', 'iiface': 'public0', 'oiface': 'mgmt0', 'protocol': 'tcp', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': [cop_nginxcop_ipv4, cop_portal_ipv4], 'port': ['443']},

        # 3.1.6 Mgmt Specific Forward IPv6
        # 3.1.6.1 Ping
        {'order': 3161, 'version': '6', 'iiface': 'public0', 'oiface': 'mgmt0', 'protocol': 'icmp', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},
        # 3.1.6.2 COP nginx and portal 443
        {'order': 3162, 'version': '6', 'iiface': 'public0', 'oiface': 'mgmt0', 'protocol': 'tcp', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': [cop_nginxcop_ipv6, cop_portal_ipv6], 'port': ['443']},

        # 3.1.7 Outbound IPv4
        # 3.1.7.1 Allow all
        {'order': 3171, 'version': '4', 'iiface': '', 'oiface': 'public0', 'protocol': 'any', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},

        # 3.1.8 Outbound IPv6
        # 3.1.8.1 Allow all
        {'order': 3181, 'version': '6', 'iiface': '', 'oiface': 'public0', 'protocol': 'any', 'action': 'accept', 'log': False, 'source': ['any'], 'destination': ['any'], 'port': []},

    ]
    win.addstr(2, 1, '3.1 Preparing Firewall Rules:            SUCCESS', curses.color_pair(2))

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
    # 4.1 Robosoc script
    win.addstr(2, 1, '4.1 RoboSOC Script and Cron job setup:          ', curses.color_pair(2))
    win.refresh()
    # 4.1.1 set the /etc/cloudcix/pod/pod_installer/robosoc.py file to executable ie to +x
    try:
        subprocess.run(['sudo', 'chmod', '+x', '/etc/cloudcix/pod/pod_installer/robosoc.py'], check=True)
    except subprocess.CalledProcessError as error:
        win.addstr(2, 1, '4.1 RoboSOC Script and Cron job setup:    FAILED', curses.color_pair(3))
        win.addstr(18, 1, f'Error: {error}', curses.color_pair(3))
        win.refresh()
        return False

    # 4.1.2 Robosoc Cron job
    with open('/etc/cron.d/robosoc', 'w') as file:
        file.write('*/15 * * * * root /etc/cloudcix/pod/pod_installer/robosoc.py > /dev/null 2>&1 \n')
    # for cron job file, file must be executable so set to +x
    try:
        subprocess.run(['sudo', 'chmod', '+x', '/etc/cron.d/robosoc'], check=True)
    except subprocess.CalledProcessError as error:
        win.addstr(2, 1, '4.1 RoboSOC Script and Cron job setup:    FAILED', curses.color_pair(3))
        win.addstr(18, 1, f'Error: {error}', curses.color_pair(3))
        win.refresh()
    win.addstr(2, 1, '4.1 RoboSOC Script and Cron job setup:   SUCCESS', curses.color_pair(2))
    win.refresh()

    # Finish
    return True
