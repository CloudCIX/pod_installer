# stdlib
import curses
import os
# libs
# local
from interface_utils import read_interface_file


def ports(win):
    # ethernet ports
    ports = os.listdir('/sys/class/net/')
    
    excluded_ports = ['lo', 'idrac', 'bonding_masters']
    
    ports = [port for port in ports if port not in excluded_ports]
    
    win.addstr(2, 35, ' Ethernet Ports:      Connected:     Status:      ', curses.color_pair(5))
    i = 0  # if no ethernet ports are detected i will be undefined and will crash win(addstr) after for loop
    for i, port in enumerate(ports):
        win.addstr(4 + i, 36, port)
        # is there a network cable is connected with network card
        status = read_interface_file(port, 'carrier')
        if '1' in status:
            win.addstr(4 + i, 57, ' up        ', curses.color_pair(4))
        elif '0' in status:
            win.addstr(4 + i, 57, ' down      ', curses.color_pair(3))
        else:
            win.addstr(4 + i, 57, ' unknown   ', curses.color_pair(3))
        # is the ethernet port up or down?
        state = read_interface_file(port, 'operstate')
        if 'up' in state:
            win.addstr(4 + i, 72, ' up        ', curses.color_pair(4))
        elif 'down' in state:
            win.addstr(4 + i, 72, ' down      ', curses.color_pair(3))
        else:
            win.addstr(4 + i, 72, ' unknown   ', curses.color_pair(3))

    win.addstr(6 + i, 36, f' {str(len(ports))} ethernet ports found                         ', curses.color_pair(5))
    win.refresh()
