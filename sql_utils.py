# stdlib
import json
import pickle   # Used for serializing/deserializing Python objects
import socket
import sqlite3
import subprocess
# lib
import yaml


__all__ = [
    'get_cidata',
    'get_instanciated_infra',
    'get_instanciated_metadata',
    'get_test_details',
    'get_test_bit_map',
    'set_up_sqlite',
]


def set_up_sqlite():
    # Create required Tables if they do not exist and clear from previous sessions
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        # Create required tables if they do not exist
        cur.execute('CREATE TABLE IF NOT EXISTS test_map (name TEXT, bit_map TEXT);')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS test_details (id INTEGER, result BLOB, fail TEXT, ignore TEXT, warn TEXT,
            fail_map TEXT, warn_map TEXT, ignore_map TEXT, pass_map TEXT);
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS session_constants (id INTEGER, cidata BLOB, instanciated_metadata BLOB,
            instanciated_infra BLOB);
        ''')
        cur.execute('CREATE TABLE IF NOT EXISTS host_details (id INTEGER, host_status INTEGER, host_status_text TEXT);')
        # Remove all data that may reside from previous sessions
        cur.execute("DELETE FROM test_map;")
        cur.execute("DELETE FROM test_details;")
        cur.execute("DELETE FROM session_constants;")
        cur.execute("DELETE FROM host_details;")
        conn.commit()

    ##  Map Host Status to Tests by ignore, warn or fail                   ##
    ##  Test map bits that are neither warn or fail are ignore by default  ##

    #                                     0b987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210
    invert                              = 0b111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    cop_validate_podnet_a_warn          = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
    cop_validate_podnet_a_fail          = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111111010111000000011111111101110
    cop_validate_podnet_b_warn          = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    cop_validate_podnet_b_fail          = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111111010111000000011111111101110
    cop_validate_appliance_a_warn       = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    cop_validate_appliance_a_fail       = 0b000000000000000000000000000000000000000000000000000000000000001100110000111110000000000010011010111000000000011100010110
    cop_install_podnet_a_warn           = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000001
    cop_install_podnet_a_fail           = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111100101111000000000000001101110
    cop_install_podnet_b_warn           = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    cop_install_podnet_b_fail           = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111100101111000000000001100001110
    cop_install_appliance_a_warn        = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    cop_install_appliance_a_fail        = 0b000000000000000000000000000000000000000000000000000000000000001100110000111110000000000010000101111000000000001100010110
    cop_reinstall_podnet_a_warn         = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    cop_reinstall_podnet_a_fail         = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111100101111000000000001100001110
    region_validate_podnet_a_warn       = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
    region_validate_podnet_a_fail       = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111111010111011111111111111101110
    region_validate_podnet_b_warn       = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    region_validate_podnet_b_fail       = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111111010111011111111111111101110
    region_validate_appliance_a_warn    = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    region_validate_appliance_a_fail    = 0b000000000000000000000000000000000000000000000000000000000000001100110100111110000000000010011010111000000000011100010110
    region_install_podnet_a_warn        = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000001
    region_install_podnet_a_fail        = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111100101111000000000000001101110
    region_install_podnet_b_warn        = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    region_install_podnet_b_fail        = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111100101111000000000001100001110
    region_install_appliance_a_warn     = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    region_install_appliance_a_fail     = 0b000000000000000000000000000000000000000000000000000000000000001100110100111110000000000010000101111000000000001100010110
    region_reinstall_podnet_a_warn      = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    region_reinstall_podnet_a_fail      = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111100101111000000000001100001110
    copregion_validate_podnet_a_warn    = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
    copregion_validate_podnet_a_fail    = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111111010111011111111111111101110
    copregion_validate_podnet_b_warn    = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    copregion_validate_podnet_b_fail    = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111111010111011111111111111101110
    copregion_validate_appliance_a_warn = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    copregion_validate_appliance_a_fail = 0b000000000000000000000000000000000000000000000000000000000000001100110100111110000000000010011010111000000000011100010110
    copregion_install_podnet_a_warn     = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000001
    copregion_install_podnet_a_fail     = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111100101111000000000000001101110
    copregion_install_podnet_b_warn     = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    copregion_install_podnet_b_fail     = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111100101111000000000001100001110
    copregion_install_appliance_a_warn  = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    copregion_install_appliance_a_fail  = 0b000000000000000000000000000000000000000000000000000000000000001100110100111110000000000010000101111000000000001100010110
    copregion_reinstall_podnet_a_warn   = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    copregion_reinstall_podnet_a_fail   = 0b000000000000000000000000000000000000000000000000000000000000001111111011111111111111111111100101111000000000001100001110
    pat_validate_podnet_a_warn          = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
    pat_validate_podnet_a_fail          = 0b000000000000000000000000000000000000000000000000000000000000001111111001111111111111111111111010111011111111111111101110
    pat_validate_podnet_b_warn          = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    pat_validate_podnet_b_fail          = 0b000000000000000000000000000000000000000000000000000000000000001111111001111111111111111111111010111011111111111111101110
    pat_validate_appliance_a_warn       = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    pat_validate_appliance_a_fail       = 0b000000000000000000000000000000000000000000000000000000000000001100110100111110000000000010011010111000000000011100010110
    pat_install_podnet_a_warn           = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000001
    pat_install_podnet_a_fail           = 0b000000000000000000000000000000000000000000000000000000000000001111111001111111111111111111100101111000000000000001101110
    pat_install_podnet_b_warn           = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    pat_install_podnet_b_fail           = 0b000000000000000000000000000000000000000000000000000000000000001111111001111111111111111111100101111000000000001100001110
    pat_install_appliance_a_warn        = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    pat_install_appliance_a_fail        = 0b000000000000000000000000000000000000000000000000000000000000001100110100111110000000000010000101111000000000001100010110
    pat_reinstall_podnet_a_warn         = 0b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000110000000000000000001
    pat_reinstall_podnet_a_fail         = 0b000000000000000000000000000000000000000000000000000000000000001111111001111111111111111111100101111000000000001100001110

    test_map = [
        ('invert', str(invert)),
        ('cop_validate_podnet_a_warn', str(cop_validate_podnet_a_warn)),
        ('cop_validate_podnet_a_fail', str(cop_validate_podnet_a_fail)),
        ('cop_validate_podnet_b_warn', str(cop_validate_podnet_b_warn)),
        ('cop_validate_podnet_b_fail', str(cop_validate_podnet_b_fail)),
        ('cop_validate_appliance_a_warn', str(cop_validate_appliance_a_warn)),
        ('cop_validate_appliance_a_fail', str(cop_validate_appliance_a_fail)),
        ('cop_install_podnet_a_warn', str(cop_install_podnet_a_warn)),
        ('cop_install_podnet_a_fail', str(cop_install_podnet_a_fail)),
        ('cop_install_podnet_b_warn', str(cop_install_podnet_b_warn)),
        ('cop_install_podnet_b_fail', str(cop_install_podnet_b_fail)),
        ('cop_install_appliance_a_warn', str(cop_install_appliance_a_warn)),
        ('cop_install_appliance_a_fail', str(cop_install_appliance_a_fail)),
        ('cop_reinstall_podnet_a_warn', str(cop_reinstall_podnet_a_warn)),
        ('cop_reinstall_podnet_a_fail', str(cop_reinstall_podnet_a_fail)),
        ('region_validate_podnet_a_warn', str(region_validate_podnet_a_warn)),
        ('region_validate_podnet_a_fail', str(region_validate_podnet_a_fail)),
        ('region_validate_podnet_b_warn', str(region_validate_podnet_b_warn)),
        ('region_validate_podnet_b_fail', str(region_validate_podnet_b_fail)),
        ('region_validate_appliance_a_warn', str(region_validate_appliance_a_warn)),
        ('region_validate_appliance_a_fail', str(region_validate_appliance_a_fail)),
        ('region_install_podnet_a_warn', str(region_install_podnet_a_warn)),
        ('region_install_podnet_a_fail', str(region_install_podnet_a_fail)),
        ('region_install_podnet_b_warn', str(region_install_podnet_b_warn)),
        ('region_install_podnet_b_fail', str(region_install_podnet_b_fail)),
        ('region_install_appliance_a_warn', str(region_install_appliance_a_warn)),
        ('region_install_appliance_a_fail', str(region_install_appliance_a_fail)),
        ('region_reinstall_podnet_a_warn', str(region_reinstall_podnet_a_warn)),
        ('region_reinstall_podnet_a_fail', str(region_reinstall_podnet_a_fail)),
        ('copregion_validate_podnet_a_warn', str(copregion_validate_podnet_a_warn)),
        ('copregion_validate_podnet_a_fail', str(copregion_validate_podnet_a_fail)),
        ('copregion_validate_podnet_b_warn', str(copregion_validate_podnet_b_warn)),
        ('copregion_validate_podnet_b_fail', str(copregion_validate_podnet_b_fail)),
        ('copregion_validate_appliance_a_warn', str(copregion_validate_appliance_a_warn)),
        ('copregion_validate_appliance_a_fail', str(copregion_validate_appliance_a_fail)),
        ('copregion_install_podnet_a_warn', str(copregion_install_podnet_a_warn)),
        ('copregion_install_podnet_a_fail', str(copregion_install_podnet_a_fail)),
        ('copregion_install_podnet_b_warn', str(copregion_install_podnet_b_warn)),
        ('copregion_install_podnet_b_fail', str(copregion_install_podnet_b_fail)),
        ('copregion_install_appliance_a_warn', str(copregion_install_appliance_a_warn)),
        ('copregion_install_appliance_a_fail', str(copregion_install_appliance_a_fail)),
        ('copregion_reinstall_podnet_a_warn', str(copregion_reinstall_podnet_a_warn)),
        ('copregion_reinstall_podnet_a_fail', str(copregion_reinstall_podnet_a_fail)),
        ('pat_validate_podnet_a_warn', str(pat_validate_podnet_a_warn)),
        ('pat_validate_podnet_a_fail', str(pat_validate_podnet_a_fail)),
        ('pat_validate_podnet_b_warn', str(pat_validate_podnet_b_warn)),
        ('pat_validate_podnet_b_fail', str(pat_validate_podnet_b_fail)),
        ('pat_validate_appliance_a_warn', str(pat_validate_appliance_a_warn)),
        ('pat_validate_appliance_a_fail', str(pat_validate_appliance_a_fail)),
        ('pat_install_podnet_a_warn', str(pat_install_podnet_a_warn)),
        ('pat_install_podnet_a_fail', str(pat_install_podnet_a_fail)),
        ('pat_install_podnet_b_warn', str(pat_install_podnet_b_warn)),
        ('pat_install_podnet_b_fail', str(pat_install_podnet_b_fail)),
        ('pat_install_appliance_a_warn', str(pat_install_appliance_a_warn)),
        ('pat_install_appliance_a_fail', str(pat_install_appliance_a_fail)),
        ('pat_reinstall_podnet_a_warn', str(pat_reinstall_podnet_a_warn)),
        ('pat_reinstall_podnet_a_fail', str(pat_reinstall_podnet_a_fail)),
    ]

    ##########################################################################
    #        Reset the Data Blob ready to return data                        #
    ##########################################################################

    number_of_tests = 58                   # The number of tests
    test_result     = []                   # A placeholder for test_results

    for i in range(number_of_tests):
        test_result.append ("")            # Set test results to blanks

    test_details_query = 'INSERT INTO test_details VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    test_details_values = (1, pickle.dumps(test_result), '', '', '', str(0b0), str(0b0), str(0b0), str(0b0))

    ##########################################################################
    ##                                                                      ##
    ##  CREATE SESSION VARIABLES                                            ##
    ##  Configuration values are read from...                               ##
    ##     1) CIDATA configuration files                                    ##
    ##     2) Host configuration files                                      ##
    ##                                                                      ##
    ##########################################################################
    cidata = create_cidata()
    instanciated_metadata = create_instanciated_metadata()
    instanciated_infra = create_instanciated_infra()

    session_query = 'INSERT INTO session_constants (id, cidata, instanciated_metadata, instanciated_infra) VALUES (?, ?, ?, ?)'
    session_values = (1, pickle.dumps(cidata), pickle.dumps(instanciated_metadata), pickle.dumps(instanciated_infra))

    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        # Add data to tables in database
        cur.executemany('INSERT INTO test_map (name, bit_map) VALUES (?, ?)', test_map)
        cur.execute(test_details_query, test_details_values)
        cur.execute(session_query, session_values)
        conn.commit()
        cur.close()


def create_cidata():
    # Metadata Session Constants
    cidata = {
       'user-data': {},
       'config.json': {},
       'env': {},
       'mountable': False,
    }
    # Mount CIDATA
    if subprocess.run(['mount', '--label', 'CIDATA', '/mnt/'], capture_output=True).returncode == 0:
        cidata['mountable'] = True
        # Read CIDATA
        # CIDATA user-data
        try:
            with open('/mnt/user-data', 'r') as file:
                cidata['user-data'] = yaml.safe_load(file)
        except FileNotFoundError:
            pass
        # CIDATA config.json
        try:
            with open('/mnt/config.json', 'r') as json_file:
                cidata['config.json'] = json.load(json_file)
        except FileNotFoundError:
            pass
        # CIDATA env
        try:
            with open('/mnt/env', 'r') as file:
                # Reading in file and converting to a dictionary for comparison tests
                lines = file.readlines()
                for line in lines:
                    line = line.strip()
                    # Skip lines that are a comment or blank
                    if line.startswith('#') or line == '':
                        continue
                    line = line.split("=")
                    cidata['env'][line[0]] = line[1].replace('"','')
        except FileNotFoundError:
            pass

    return cidata


def create_instanciated_infra():
    # Instanciated Infra Constants
    # netplan
    instanciated_infra = {
        'netplan': {},
        'hostname': '',
    }
    # netplan
    try:
        with open('/etc/netplan/00-installer-config.yaml', 'r') as file:
            instanciated_infra['netplan'] = yaml.safe_load(file)
    except FileNotFoundError:
        pass
    # hostname
    hostname = socket.gethostname()
    instanciated_infra['hostname'] = hostname

    return instanciated_infra


def create_instanciated_metadata():
    # Instanciated Session Constants
    instanciated_metadata = {
       'config.json': {},
       '.env': {},
    }
    # Instanciated config.json
    try:
        with open('/etc/cloudcix/pod/configs/config.json', 'r') as file:
            instanciated_metadata['config.json'] = json.load(file)
    except FileNotFoundError:
        pass
    # Instanciated env
    try:
        with open('/etc/cloudcix/docker/.env', 'r') as file:
            # Reading in file and converting to a dictionary for comparison tests
            lines = file.readlines()
            for line in lines:
                line = line.strip()
                # Skip lines that are a comment or blank
                if line.startswith('#') or line == '':
                    continue
                line = line.split("=")
                instanciated_metadata['.env'][line[0]] = line[1].replace('"','')
    except FileNotFoundError:
        pass

    return instanciated_metadata


def get_cidata():
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute(f'SELECT cidata FROM session_constants WHERE id = 1;')
        cidata = cur.fetchone()[0]
        cur.close()

    return pickle.loads(cidata)


def get_test_bit_map(name):
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT bit_map FROM test_map WHERE name = '{name}'")
        bit_map = cur.fetchone()[0]
        cur.close()

    return int(bit_map)


def get_host_details():
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute(f'SELECT host_status, host_status_text FROM host_details WHERE id = 1;')
        details = cur.fetchone()
        cur.close()

    return details[0], details[1]


def get_instanciated_metadata():
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute(f'SELECT instanciated_metadata FROM session_constants WHERE id = 1;')
        instanciated_metadata = cur.fetchone()[0]
        cur.close()

    return pickle.loads(instanciated_metadata)


def get_instanciated_infra():
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute(f'SELECT instanciated_infra FROM session_constants WHERE id = 1;')
        instanciated_infra = cur.fetchone()[0]
        cur.close()

    return pickle.loads(instanciated_infra)


def get_test_details():
    # result BLOB, fail TEXT, ignore TEXT, warn TEXT, fail_map TEST, warn_map TEXT, ignore_map TEXT, pass_map TEXT
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute('''
            SELECT result, fail, ignore, warn, fail_map, warn_map, ignore_map, pass_map FROM test_details WHERE id = 1;
        ''')
        details = cur.fetchone()
        cur.close()
    
    result = pickle.loads(details[0])
    fail = int(details[1])
    ignore = int(details[2])
    warn = int(details[3])
    fail_map = int(details[4])
    warn_map = int(details[5])
    ignore_map = int(details[6])
    pass_map = int(details[7])

    return result, fail, ignore, warn, fail_map, warn_map, ignore_map, pass_map


def get_test_results():
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute('SELECT fail_map, warn_map, pass_map, result FROM test_details WHERE id = 1;')
        details = cur.fetchone()
        cur.close()
    
    fail_map = int(details[0])
    warn_map = int(details[1])
    pass_map = int(details[2])
    result = pickle.loads(details[3])
    
    return pass_map, warn_map, fail_map, result


def insert_host_status(host_status, host_status_text):
    query = f"INSERT INTO host_details VALUES (?, ?, ?);"
    values = (1, host_status, host_status_text)
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute(query, values)
        conn.commit()
        cur.close()
    return None


def update_fail_map(fail_map):
    query = 'UPDATE test_details SET fail_map = ? WHERE id = 1;'
    values = (str(fail_map),)
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute(query, values)
        conn.commit()
        cur.close()
    
    return None


def update_test_details(result, fail, ignore, warn, fail_map, warn_map, ignore_map, pass_map):
    query = ('''
        UPDATE test_details SET result = ?, fail = ?, ignore = ?, warn = ?, fail_map = ?, warn_map = ?,
         ignore_map = ?, pass_map = ? WHERE id = 1;
    ''')
    values = (
        pickle.dumps(result), str(fail), str(ignore), str(warn), str(fail_map), str(warn_map),
        str(ignore_map), str(pass_map)
    )
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute(query, values)
        conn.commit()
        cur.close()
    
    return None


def update_test_levels(fail, ignore, warn):
    query = (
        f"UPDATE test_details SET fail = ?, ignore = ?, warn = ? WHERE id = 1;"
    )
    values = (str(fail), str(ignore), str(warn))
    with sqlite3.connect('/etc/cloudcix/pod/installer.db') as conn:
        cur = conn.cursor()
        cur.execute(query, values)
        conn.commit()
        cur.close()
    
    return None
