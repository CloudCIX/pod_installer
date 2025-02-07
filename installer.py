#!/etc/cloudcix/pod/pod_installer/.venv/bin/python3
# stdlib
import curses
import os
# libs
# local
import data_blob
from installer_scripts import (
    cop_install_appliance_a,
    cop_install_podnet_a,
    cop_install_podnet_b,
    cop_reinstall_podnet_a,
    copregion_install_appliance_a,
    copregion_install_podnet_a,
    copregion_install_podnet_b,
    copregion_reinstall_podnet_a,
    pat_install_appliance_a,
    pat_install_podnet_a,
    pat_install_podnet_b,
    pat_reinstall_podnet_a,
    region_install_appliance_a,
    region_install_podnet_a,
    region_install_podnet_b,
    region_reinstall_podnet_a,
)
from logo import logo


class ScreenTooSmallError(Exception):
    """Raise when the screen is too small to display information properly """


dir_path = os.path.dirname(os.path.realpath(__file__))

# Setting up the Screen
# Create a screen
stdscr = curses.initscr()
# Allows use of Keyboard Control
stdscr.keypad(True)
# Hide the cursor
curses.curs_set(0)
# Initialise color
curses.start_color()
# Normal Text
curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
# Highlighted Text
curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLUE)
# Failed Verification
curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_RED)
# Passed Verification
curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_GREEN)
# Passed Verification
curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_YELLOW)
curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_BLUE)
curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_MAGENTA)
curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_WHITE)

# Standard Background
stdscr.bkgd(' ', curses.color_pair(1))

# Setting up Global Constants
# Size of window
rows, cols = stdscr.getmaxyx()
# Leave a black border
rows = rows - 2
# Find the middle row to centre win
rowmid = int(rows / 2)
# Leave a black border
cols = cols - 2
# Find the middle column to cente win
colmid = int(cols / 2)
# Space out the menu items
if int(cols / 6) <= 16:
    delta = int(cols / 6)
else:
    # But not too far apart
    delta = 16


tabs_list = ['Pod Utility']
menu_list = ['Test Results', 'Configure', 'Errors']


def copyright():
    banner(True, 'header')
    win = curses.newwin(23, 84, 5, colmid - 42)
    with open(f'{dir_path}/copyright.txt') as file:
        copyright_text = file.read()
    try:
        win.addstr(1, 1, copyright_text)
        banner(False, 'agree')
    except curses.error:
        pass
    win.refresh()
    user_input = stdscr.getkey()
    while user_input != '\n':
        user_input = win.getkey()


def summary():
    win = curses.newwin(20, 84, 8, colmid - 42)
    summary_header = '                                   Pod Summary                                   '
    win.addstr(3, 1, summary_header, curses.color_pair(4))
    win.addstr(5, 20, f'Host Status:      {host_status_text} ({host_status})')
    verified, failed, warnings, ignored = 0, 0, 0, 0
    for i in test_result:
        if 'Pass' in i:
            verified += 1
        elif 'Fail' in i:
            failed += 1
        elif 'Warn' in i:
            warnings += 1
        elif 'Ignore' in i:
            ignored += 1
    win.addstr(7, 20,  'Test Results:', curses.color_pair(5))
    win.addstr(8, 22,  f'Verified        {verified}')
    win.addstr(9, 22,  f'Failed          {failed}')
    win.addstr(10, 22, f'Warning         {warnings}')
    win.addstr(11, 22, f'Ignored         {ignored}')
    win.addstr(12, 22,  '               -----')
    win.addstr(13, 22, f'                {len(test_result)}')
    win.refresh()


def edit_mode(x):
    if x:
        msg = f'{"Edit the existing value and press Enter...":^{cols}}'
        stdscr.addstr(2, (cols - 12), ' Edit Mode ', curses.A_BOLD | curses.color_pair(5))
        stdscr.addstr(34, 1, msg, curses.A_BOLD | curses.A_REVERSE)
    else:
        msg = f'{"Use Arrows to Navigate and Enter to select...":^{cols}}'
        stdscr.addstr(2, (cols - 12), '           ', curses.A_REVERSE)
        stdscr.addstr(34, 1, msg, curses.A_BOLD | curses.A_REVERSE)
    stdscr.refresh()


def banner(clear, message):
    def line(y, x):
        stdscr.addstr(y, 1, '=' * x, curses.A_BOLD | curses.A_REVERSE)

    if clear:
        stdscr.clear()
    if message == 'header':
        line(1, cols)
        msg = f'{"CloudCIX Pod Install Utility         Version Date: 7th Feb 2025":^{cols}}'
        stdscr.addstr(2, 1, msg, curses.A_BOLD | curses.A_REVERSE)
        line(3, cols)
    elif message == 'footer':
        line(33, cols)
        msg = f'{"Use Arrows to Navigate and Enter to select...":^{cols}}'
        stdscr.addstr(34, 1, msg, curses.A_BOLD | curses.A_REVERSE)
        line(35, cols)
    elif message == 'agree':
        line(33, cols)
        stdscr.addstr(34, 1, f'{"Press Enter to Agree and Continue...":^{cols}}', curses.A_BOLD | curses.A_REVERSE)
        line(35, cols)
    elif message == 'accept':
        line(33, cols)
        msg = f'{"Use Arrows to Navigate and Enter to select...":^{cols}}'
        stdscr.addstr(34, 1, msg, curses.A_BOLD | curses.A_REVERSE)
        line(35, cols)
    elif message == 'navigate':
        line(33, cols)
        msg = f'{"Use Arrows to Navigate, Enter to select and Esc to Exit...":^{cols}}'
        stdscr.addstr(34, 1, msg, curses.A_BOLD | curses.A_REVERSE)
        line(35, cols)
    elif message == 'confirm':
        line(33, cols)
        msg = f'{"Press Y to confirm or any other key to abort!":^{cols}}'
        stdscr.addstr(34, 1, msg, curses.A_BOLD | curses.A_REVERSE)
        line(35, cols)

    stdscr.refresh()


def help_message(message):
    for i in range(0, 3):
        stdscr.addstr(29 + i, colmid - 42, ' ' * 90)
        stdscr.addstr(29 + i, colmid - 42, message[i], curses.color_pair(1))
    stdscr.refresh()


def main_menu(stdscr):
    # The main (horizontal) menu
    logo(stdscr, 8, cols - 55)
    for count, column in enumerate(tabs_list):
        if count == tab_item:
            stdscr.addstr(5, 2 + count * delta, column, curses.color_pair(2) | curses.A_BOLD)
        else:
            stdscr.addstr(5, 2 + count * delta, column, curses.color_pair(1) | curses.A_BOLD)
    stdscr.refresh()


def build(win, subitem, stdscr, colmid):
    if subitem == 0:
        # Test Results
        if fail_map == 0:
            msg = f'All good, no tests have failed for {host_status_text}'
            win.addstr(3, 1, msg, curses.color_pair(4))
        else:
            fails = []
            for i in test_result:
                if 'Fail' in i:
                    fails.append(i)

            if len(fails) == 0:
                # Could not determine host status to run tests.
                win.addstr(3, 1, 'Could not determine host status to run tests', curses.color_pair(3))
            else:
                msg = f'{len(fails)}/{len(test_result)} Tests Failed for {host_status_text}'
                win.addstr(3, 1, msg, curses.color_pair(3))
                msg = 0
                line = 5
                while msg < min(len(fails), 10):
                    win.addstr(line, 1, fails[msg])
                    line += 1
                    msg += 1
        line1 = 'Summary of Test Results.'
        stdscr.addstr(29, colmid - 42, line1, curses.color_pair(1))
        stdscr.refresh()
        win.refresh()
        win.getch()
    elif subitem == 1:
        line1 = 'This menu will configure the Pod.'
        stdscr.addstr(29, colmid - 42, line1, curses.color_pair(1))
        stdscr.refresh()
        # Configure Pod
        if fail_map == 0:
            win.addstr(1, 1, 'Configure Pod')
            win.refresh()
            win.getch()

            if host_status == data_blob.cop_install_podnet_a:
                built = cop_install_podnet_a.build(win)
            elif host_status == data_blob.cop_install_podnet_b:
                built = cop_install_podnet_b.build(win)
            elif host_status == data_blob.cop_install_appliance_a:
                built = cop_install_appliance_a.build(win)
            elif host_status == data_blob.cop_reinstall_podnet_a:
                built = cop_reinstall_podnet_a.build(win)
            elif host_status == data_blob.region_install_podnet_a:
                built = region_install_podnet_a.build(win)
            elif host_status == data_blob.region_install_podnet_b:
                built = region_install_podnet_b.build(win)
            elif host_status == data_blob.region_install_appliance_a:
                built = region_install_appliance_a.build(win)
            elif host_status == data_blob.region_reinstall_podnet_a:
                built = region_reinstall_podnet_a.build(win)
            elif host_status == data_blob.copregion_install_podnet_a:
                copregion_install_podnet_a.build(win)
            elif host_status == data_blob.copregion_install_podnet_b:
                built = copregion_install_podnet_b.build(win)
            elif host_status == data_blob.copregion_install_appliance_a:
                built = copregion_install_appliance_a.build(win)
            elif host_status == data_blob.copregion_reinstall_podnet_a:
                built = copregion_reinstall_podnet_a.build(win)
            elif host_status == data_blob.pat_install_podnet_a:
                built = pat_install_podnet_a.build(win)
            elif host_status == data_blob.pat_install_podnet_b:
                built = pat_install_podnet_b.build(win)
            elif host_status == data_blob.pat_install_appliance_a:
                built = pat_install_appliance_a.build(win)
            elif host_status == data_blob.pat_reinstall_podnet_a:
                built = pat_reinstall_podnet_a.build(win)
            else:
                built = False
                win.addstr(3, 1, f'Host {host_status}, is already in a configured state.', curses.color_pair(4))

            if built is True:
                win.clear()
                win.addstr(3, 1, f'Successfully Built the Host: {host_status_text}, Press ENTER to go to Summary Tab.')
                win.refresh()
                user_input = win.getkey()
                while user_input != '\n':
                    user_input = win.getkey()
                return True
        else:
            win.addstr(3, 1, 'One or more Tests have failed, cannot configure Pod', curses.color_pair(3))
        win.refresh()
        win.getch()

    elif subitem == 2:
        # Collect errors from /etc/cloudcix/pod/pod_installer/error.txt
        error_file = '/etc/cloudcix/pod/pod_installer/error.txt'
        with open(error_file, 'r') as file:
            collected_error = file.read()
        if len(collected_error) > 0:
            msg = f'No errors collected in {error_file}'
        else:
            msg = collected_error
        win.addstr(3, 1, msg, curses.color_pair(3))
        line1 = 'Collected errors are:'
        stdscr.addstr(29, colmid - 42, line1, curses.color_pair(1))
        stdscr.refresh()
        win.refresh()
        win.getch()


def edit_window(stdscr):
    # The rectangular window containing either the submenu of the selected submenu functionality

    # This is where edit_window kicks off...
    global subitem
    go = True
    while go:
        # Create the Vertical Submenu
        for count, row in enumerate(menu_list):
            if count == subitem:
                stdscr.addstr(7 + count, 4, row, curses.color_pair(2) | curses.A_BOLD)
            else:
                stdscr.addstr(7 + count, 4, row, curses.color_pair(1) | curses.A_BOLD)
        stdscr.refresh()

        # Now go navigate the Vertical Submenu
        char = stdscr.getch()
        if char == curses.KEY_DOWN and subitem == len(menu_list) - 1:
            subitem = 0
        elif char == curses.KEY_DOWN and subitem < len(menu_list) - 1:
            subitem += 1
        elif char == curses.KEY_UP and subitem == 0:
            go = False
        elif char == curses.KEY_UP and subitem > 0:
            subitem -= 1
        elif char == 27:
            subitem = 0
            go = False

        # User has selected an item from the vertical submenu
        if char == curses.KEY_ENTER or char in [10, 13]:
            # User has selected from the menu
            # Overwrite previous menu_list[subitem]
            stdscr.addstr(7, colmid - 42, ' ' * 35)
            stdscr.addstr(7, colmid - 42, ' ' + menu_list[subitem] + ' ', curses.color_pair(2))
            stdscr.refresh()
            win = curses.newwin(20, 84, 8, colmid - 42)
            win.keypad(True)
            # Validate and Build is always a last Tab
            if build(win, subitem, stdscr, colmid) is True:
                main(stdscr, False)

        banner(True, 'header')
        banner(False, 'footer')

        main_menu(stdscr)
        banner(False, 'header')
        banner(False, 'navigate')


def main(stdscr, firsttime=True):

    # Make sure the screen is big enough
    if (rows < 35) or (cols < 90):
        raise ScreenTooSmallError('Screen is too small')

    # Clear keyboard inputs that may have been entered by user during delay screen.
    curses.flushinp()

    if firsttime is True:
        copyright()

    global tab_item, subitem, host_status, host_status_text, pass_map, warn_map, fail_map, test_result

    host_status, host_status_text, pass_map, warn_map, fail_map, test_result = data_blob.data_blob()
    tab_item = 0
    subitem = 0

    while True:
        # setup type based loading global params
        banner(True, 'header')
        banner(False, 'footer')
        main_menu(stdscr)
        stdscr.refresh()
        summary()
        char = stdscr.getch()

        if char == curses.KEY_RIGHT and tab_item < len(tabs_list) - 1:
            tab_item += 1
        elif char == curses.KEY_RIGHT and tab_item == len(tabs_list) - 1:
            tab_item = 0
        elif char == curses.KEY_LEFT and tab_item > 0:
            tab_item -= 1
        elif char == curses.KEY_LEFT and tab_item == 0:
            tab_item = len(tabs_list) - 1
        elif char == curses.KEY_ENTER or char == curses.KEY_DOWN or char in [10, 13]:
            # Clear Summary Window in selected submenu Submenu
            banner(True, 'header')
            banner(False, 'footer')
            banner(False, 'navigate')
            main_menu(stdscr)
            stdscr.refresh()
            # A submenu was selected, so go process it in the edit_window
            edit_window(stdscr)
        # No submenu was selected, so go around the loop again


try:
    curses.wrapper(main)
except ScreenTooSmallError as e:
    print(str(e))
