# Region Install Appliance A Configuration
# stdlib
import json
import ipaddress
import subprocess
# libs
import curses
import yaml
from cloudcix.rcc import comms_ssh, CHANNEL_SUCCESS, CONNECTION_ERROR
# local
from sql_utils import get_instanciated_infra, get_instanciated_metadata

SUCCESS_CODE = 0


def update_netplan_config_routes(interface, target_route_to, new_route_values):
    netplan_config = get_instanciated_infra()['netplan']

    # Check if the ethernet interface exists in the configuration
    if interface in netplan_config['network']['ethernets']:
        # Get the routes for the interface
        routes = netplan_config['network']['ethernets'][interface].get('routes', [])

        # Update the existing route
        route_found = False
        for route in routes:
            if route.get('to') == target_route_to:
                route.update(new_route_values)
                route_found = True
                break
        # Add new route if not exist before
        if route_found is False:
            routes.append(new_route_values)

        # Write the updated configuration back to the file
        with open('/etc/netplan/00-installer-config.yaml', 'w') as file:
            yaml.safe_dump(netplan_config, file, default_flow_style=False)

        # Apply the new configuration
        try:
            subprocess.run(
                'sudo netplan apply > /dev/null 2>&1',
                shell=True,
                check=True,
            )
            return True, f'Applied updated netplan configuration for {interface}.'
        except subprocess.CalledProcessError as error:
            return False, f'Error occurred while applying netplan configuration: {error}'
    else:
        return False, f'Interface {interface} not found in the netplan configuration.'


def disable_robot_password_ssh(podnet_ip):
    # move the robot.conf from /etc/cloudcix/pod/templates/robot.conf to /etc/ssh/sshd_config.d/robot.conf
    payload = """
if ! echo "Match user robot\nPasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/robot.conf > /dev/null 2>&1; then
    echo "300: Failed to create /etc/ssh/sshd_config.d/robot.conf"
    exit 1
fi 
if ! sudo systemctl restart ssh > /dev/null 2>&1; then
    echo "301: Failed to restart sshd service"
    exit 1
fi
echo "000: Successfully created /etc/ssh/sshd_config.d/robot.conf and restarted sshd service"
    """
    # Deploy the bash script to the Host
    ret = comms_ssh(
        host_ip=podnet_ip,
        payload=payload,
        username='robot',
    )
    if ret['channel_code'] != CHANNEL_SUCCESS:
        return False, f'{ret["channel_message"]}\nError: {ret["channel_error"]}'
    if ret['payload_code'] != SUCCESS_CODE:
        return False, f'{ret["payload_message"]}\nError: {ret["payload_error"]}'

    return True, ret["payload_message"]


def upload_ssh_key(podnet):
    # Note: password `cloudcix` is set during ISO preparation.
    os_cmd = 'sshpass -p cloudcix ssh-copy-id '
    os_cmd += '-o StrictHostKeyChecking=no '
    os_cmd += f'-i "/home/administrator/.ssh/id_rsa.pub" '
    os_cmd += f'robot@{podnet} > /dev/null 2>&1'
    try:
        subprocess.run(os_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as error:
        return False, error
    return True, ''


def collect_error(error_msg, width):
    if 1 + len(error_msg) > width:
        filepath = '/etc/cloudcix/pod/pod_installer/error.txt'
        with open(filepath, 'w') as file:
            file.write(error_msg)
        return f'Error size is out of window size, check `Error` menu for complete error.'
    else:
        return error_msg


def build(win):
    width = win.getmaxyx()[1]
    config = get_instanciated_metadata()['config.json']

    # 1 Network Setup
    # 1.1 Public Interface
    # Appliance has no Public Interface

    # 1.2 Management Interface
    # Management Interface is already configured by cloud-init's user-data for Appliance A

    # 1.3 Recovery Interface
    # Appliance has no Recovery Interface

    # 1.4 Private Interface
    # Appliance has no Private Interface

    # 1.5 Inter Interface
    # Appliance has no Inter Interface

    # 2 Update config.json
    # Management Interface is the only interface logical name to be updated in config.json
    win.addstr(1, 1, '2. Update Config json:                          ', curses.color_pair(2))
    win.refresh()
    # 2.1 Update Interface names
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
        'appliance_a_mgmt_ifname': mgmt_iflname,
    }
    with open('/etc/cloudcix/pod/configs/config.json', 'r') as file:
        config_json = json.load(file)
    updated_config = {key: logical_ifnames.get(key, val) for key, val in config_json.items()}
    with open('/etc/cloudcix/pod/configs/config.json', 'w') as file:
        json.dump(updated_config, file, indent=4)
    win.addstr(1, 1, '2. Update Config json:                   SUCCESS', curses.color_pair(4))

    win.addstr(18, 1, f'Please press ENTER to continue Docker setup block.        ', curses.color_pair(2))
    win.refresh()
    user_input = win.getkey()
    while user_input != '\n':
        user_input = win.getkey()
    win.clear()

    # 3 Firewall setup
    # Not Applicable for Appliance

    # 4 RoboSOC setup
    # Not Applicable for Appliance

    # 5 Docker setup
    win.addstr(1, 1, '5 Docker Setup:                                 ', curses.color_pair(2))
    # 5.1 Download the docker-compose.yml file from github
    win.addstr(2, 1, '5.1 Dowloading the docker-compose.yml:          ', curses.color_pair(2))
    win.refresh()
    try:
        subprocess.run(
            'curl https://raw.githubusercontent.com/CloudCIX/pod_yaml/master/region/docker-compose.yml -o /etc/cloudcix/docker/docker-compose.yml > /dev/null 2>&1',
            shell=True,
            check=True,
        )
        win.addstr(2, 1, '5.1 Dowloading the docker-compose.yml:   SUCCESS', curses.color_pair(4))
        win.refresh()
    except subprocess.CalledProcessError as error:
        win.addstr(2, 1, '5.1 Dowloading the docker-compose.yml:    FAILED', curses.color_pair(3))
        win.addstr(18, 1, collect_error(error, width), curses.color_pair(3))
        win.refresh()
        return False

    # 5.2 Download default.conf.template file from github for cop blend
    win.addstr(3, 1, '5.2 Dowloading the default.conf.template:    N/A', curses.color_pair(2))
    win.refresh()

    # 5.3 Start Docker services
    win.addstr(4, 1, '5.3 Starting Docker services:                   ', curses.color_pair(2))
    win.refresh()
    try:
        subprocess.run(
            'sudo docker compose --file /etc/cloudcix/docker/docker-compose.yml up -d  > /dev/null 2>&1',
            shell=True,
            check=True,
        )
        win.addstr(4, 1, '5.3 Starting Docker services:            SUCCESS', curses.color_pair(4))
        win.refresh()
    except subprocess.CalledProcessError as error:
        win.addstr(4, 1, '5.3 Starting Docker services:             FAILED', curses.color_pair(3))
        win.addstr(18, 1, collect_error(error, width), curses.color_pair(3))
        win.refresh()
        return False

    # 5.4 Setup Cron job for User expiration notifications
    win.addstr(5, 1, '5.4 User expiration notifications:           N/A', curses.color_pair(2))
    win.refresh()

    # 5.5 Setup Cron job for backing up API PGSQL database
    win.addstr(6, 1, '5.5 Backing up API PGSQL database:           N/A', curses.color_pair(2))
    win.refresh()

    # 5.6 Reset Robot password less access on PodNet A
    win.addstr(7, 1, '5.6 Reset Robot password less access on PodNet A:', curses.color_pair(2))
    win.refresh()
    network6 = config['ipv6_subnet'].split('/')[0]
    podnet_a = f'{network6}10:0:2'
    # disable robot user ssh password access
    if disable_robot_password_ssh(podnet_a):
        win.addstr(7, 1, '5.6 Reset Robot password less access on PodNet A:  SUCCESS', curses.color_pair(4))
        win.refresh()
    else:
        win.addstr(7, 1, '5.6 Reset Robot password less access on PodNet A:   FAILED', curses.color_pair(3))
        win.refresh()
        return False

    # 5.7 Reset Robot password less access on Podnet B
    win.addstr(8, 1, '5.7 Reset Robot password less access on PodNet B:         ', curses.color_pair(2))
    win.refresh()
    podnet_b = f'{network6}10:0:3'
    # disable robot user ssh password access
    if disable_robot_password_ssh(podnet_b):
        win.addstr(8, 1, '5.7 Reset Robot password less access on PodNet B:  SUCCESS', curses.color_pair(4))
        win.refresh()
    else:
        win.addstr(8, 1, '5.7 Reset Robot password less access on PodNet B:   FAILED', curses.color_pair(3))
        win.refresh()
        return False

    # 5.8 Delete `pat` user's SSH key pair on Appliance
    win.addstr(9, 1, '5.8 Delete `pat` user SSH key pair on Appliance:          ', curses.color_pair(2))
    win.refresh()
    try:
        subprocess.run(
            'sudo rm /home/pat/.ssh/id_rsa && sudo rm /home/pat/.ssh/id_rsa.pub',
            shell=True,
            check=True,
        )
        win.addstr(9, 1, '5.8 Delete `pat` user SSH key pair on Appliance:   SUCCESS', curses.color_pair(4))
        win.refresh()
    except subprocess.CalledProcessError as error:
        win.addstr(9, 1, '5.8 Delete `pat` user SSH key pair on Appliance:    FAILED', curses.color_pair(3))
        win.addstr(18, 1, collect_error(error, width), curses.color_pair(3))
        win.refresh()
        return False

    win.addstr(18, 1, f'Please press ENTER to continue Reset Network Routes block.', curses.color_pair(2))
    win.refresh()
    user_input = win.getkey()
    while user_input != '\n':
        user_input = win.getkey()
    win.clear()

    # 8 Reset Network Routes
    win.addstr(1, 1, '8 Reset Network Routes:                         ', curses.color_pair(2))
    # 8.1 Reset the ipv4 default route to pms1
    win.addstr(2, 1, '8.1 Reset Management IPv4 default route:        ', curses.color_pair(2))
    win.refresh()
    config_data = get_instanciated_metadata()['config.json']
    primary_ipv4_subnet_items = config_data['primary_ipv4_subnet'].split('/')
    pms1 = f'{ipaddress.ip_address(primary_ipv4_subnet_items[0]) + 1}'
    target_route_to = 'default'
    new_route_values = {
        'to': target_route_to,
        'via': pms1
    }
    success, error = update_netplan_config_routes(mgmt_iflname, target_route_to, new_route_values)
    if success is True:
        win.addstr(2, 1, '8.1 Reset Management IPv4 default route: SUCCESS', curses.color_pair(4))
        win.refresh()
    else:
        win.addstr(2, 1, '8.1 Reset Management IPv4 default route:  FAILED', curses.color_pair(3))
        win.addstr(18, 1, collect_error(error, width), curses.color_pair(3))
        win.refresh()
        return False

    # 8.2 Reset the ipv6 default route to ::10:0:1
    win.addstr(3, 1, '8.2 Reset Management IPv6 default route:        ', curses.color_pair(2))
    win.refresh()
    target_route_to = '::/0'
    ipv6_gateway = f'{config_data["ipv6_subnet"].split("/")}10:0:1'
    new_route_values = {
        'to': target_route_to,
        'via': ipv6_gateway
    }
    success, error = update_netplan_config_routes(mgmt_iflname, target_route_to, new_route_values)
    if success is True:
        win.addstr(3, 1, '8.2 Reset Management IPv6 default route: SUCCESS', curses.color_pair(4))
        win.refresh()
    else:
        win.addstr(3, 1, '8.2 Reset Management IPv6 default route:  FAILED', curses.color_pair(3))
        win.addstr(18, 1, collect_error(error, width), curses.color_pair(3))
        win.refresh()
        return False

    # Finish
    return True
