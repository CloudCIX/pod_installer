#################################################################################
#                                                                               #
#  PURPOSE OF MODULE                                                            #
#-------------------------------------------------------------------------------#
# This MODULE produces a blob of data to populate the installer GUI             #
# The data blob describes every property of the host and identifies             #
#   invalid or inconsistant data                                                #
# Think of it as an API read backend for the installer GUI                      #
# It is not concerned about GUI or update operations                            #
#                                                                               #
#===============================================================================#
#                                                                               #
#  HOST STATUS                                                                  #
#-------------------------------------------------------------------------------#
# The program establishes a 'host-status' state for the host being run          #
#     a) 'host' is derived from the hostname of the host running the program    #
#     b) 'status' is based on                                                   #
#           i)  whether CIDATA USB is plugged in                                #
#           ii) if CIDATA is plugged in, whether podnet-b is enabled            #
#     There are seven possible 'host-status'                                    #
#                                                                               #
#===============================================================================#
#                                                                               #
#  DATA CONSTANT BIT MAPS                                                       #
#-------------------------------------------------------------------------------#
#   The program checks consistency by performing comparisons called tests       #
#   Each test has a function call and test limit values are passed in the call  #
#   Each test has an id from 0 up, called the test_id                           #
#   Each test has a test_bit uses to index bit strings test_bit = test_id ** 2  #
#   The test_bit is used for bitwise operations on binary numbers called maps   #
#     Data Constant Maps                                                        #
#       For each of the seven 'host-status'                                     #
#         A 'warn' map is hard coded to identify tests that are                 #
#            warning for this host-status                                       #
#         A 'fail' map is hard coded to identify tests that are                 #
#            failing for this host-status                                       #
#         A 'ignore' map is computed each test not a 'warn' or 'fail'           #
#                                                                               #
#   Thus this progam has 21 data constant bit maps (one bit per test)           #
#                                                                               #
#===============================================================================#
#                                                                               #
#  PER HOST-STATUS VALIDATION (Performing the Tests)                            #
#-------------------------------------------------------------------------------#
# The program checks the validity of the 'host-status' by a set of tests        #
#   Each test is a comparison. Six types of tests exist...                      #
#                                                                               #
# There are four data types to compare...                                       #
#    1) 'CIDATA' are the contents of the CIDATA USB Stick                       #
#         Loaded into dictionaries                                              #
#    2) 'instanciated infra' is the way the host is currently configured        #
#         Read by sys calles to the host                                        #
#    3) 'instanciated metadata' is the contents of the data files on the host   #
#         Loaded into dictionaries                                              #
#    4) 'test values', hard coded limits                                        #
#         Sent as params to the test procedures                                 #
#                                                                               #
# Graph theory suggests that with four nodes(data types) there are six edges    #
# plus four loop edges (= 10 test types):                                       #
#    1)  CIDATA                 versus instanciated infra                       #
#    2)  CIDATA                 versus instanciated metadata                    #
#    3)  CIDATA                 versus test values                              #
#    4)  instanciated infra     versus instanciated metadata                    #
#    5)  instanciated infra     versus test values                              #
#    6)  instanciated metadata  versus test values                              #
#    7)  CIDATA                 versus CIDATA                                   #
#    8)  instanciated infra     versus instanciated infra                       #
#    9)  instanciated metadata  versus instanciated metadata                    #
#    10) test value             versus test value                               #
#                                                                               #
#===============================================================================#
#                                                                               #
#  RETURNING VALIDATED DATA                                                     #
#-------------------------------------------------------------------------------#
#  This program is run as a function whose job is to return a blob of data      #
#  data to be utilised by the GUI. This is the returned data blob definition    #
#                                                                               #
#  i)    host_status and host_status_text                                       #
#  Bit Maps                                                                     #
#  ii)   The 'pass_map' showing the tests with a pass                           #
#  iii)  The 'warn_map' showing the tests with a warn                           #
#  iv)   The 'fail_map' showing the tests with a fail                           #
#  Test Result Dictionary                                                       #
#  v)    A list of test_result with key = test_id                               #
#                                                                               #
#################################################################################

# stdlib
# lib
# local
from sql_utils import (
    get_cidata,
    get_host_details,
    get_instanciated_infra,
    get_instanciated_metadata,
    get_test_bit_map,
    get_test_results,
    insert_host_status,
    set_up_sqlite,
    update_fail_map,
    update_test_levels,
)
from tests import *


__all__ = [
    'data_blob',
]


##  Host Status Bitwise Encoding  ##
# blend (bits 1 to 4)
cop, region, copregion, pat = 2, 4, 6, 7

# status (bits 7 to 9)
validate, install, reinstall = 64, 128, 256

# hostname (bits 12 up with 14 blank to allow for podnet_c in the future)
podnet_a, podnet_b, appliance_a = 4096, 8192, 32768

# host_status
cop_validate_podnet_a          = cop        + validate    + podnet_a     # 4162
cop_validate_podnet_b          = cop        + validate    + podnet_b     # 8258
cop_validate_appliance_a       = cop        + validate    + appliance_a  # 32834
cop_install_podnet_a           = cop        + install     + podnet_a     # 4226
cop_install_podnet_b           = cop        + install     + podnet_b     # 8322
cop_install_appliance_a        = cop        + install     + appliance_a  # 32898
cop_reinstall_podnet_a         = cop        + reinstall   + podnet_a     # 4354
region_validate_podnet_a       = region     + validate    + podnet_a     # 4164
region_validate_podnet_b       = region     + validate    + podnet_b     # 8260
region_validate_appliance_a    = region     + validate    + appliance_a  # 32836
region_install_podnet_a        = region     + install     + podnet_a     # 4228
region_install_podnet_b        = region     + install     + podnet_b     # 8324
region_install_appliance_a     = region     + install     + appliance_a  # 32900
region_reinstall_podnet_a      = region     + reinstall   + podnet_a     # 4356
copregion_validate_podnet_a    = copregion  + validate    + podnet_a     # 4166
copregion_validate_podnet_b    = copregion  + validate    + podnet_b     # 8262
copregion_validate_appliance_a = copregion  + validate    + appliance_a  # 32838
copregion_install_podnet_a     = copregion  + install     + podnet_a     # 4230
copregion_install_podnet_b     = copregion  + install     + podnet_b     # 8326
copregion_install_appliance_a  = copregion  + install     + appliance_a  # 32902
copregion_reinstall_podnet_a   = copregion  + reinstall   + podnet_a     # 4358
pat_validate_podnet_a          = pat        + validate    + podnet_a     # 4167
pat_validate_podnet_b          = pat        + validate    + podnet_b     # 8263
pat_validate_appliance_a       = pat        + validate    + appliance_a  # 32839
pat_install_podnet_a           = pat        + install     + podnet_a     # 4231
pat_install_podnet_b           = pat        + install     + podnet_b     # 8327
pat_install_appliance_a        = pat        + install     + appliance_a  # 32903
pat_reinstall_podnet_a         = pat        + reinstall   + podnet_a     # 4359


def data_blob():

    set_up_sqlite()

    # CIDATA dictionary mountable will be True if CIDATA USB is mounted
    cidata = get_cidata()
    if cidata['mountable'] is True:
        podnet_b_enabled = cidata['config.json'].get('podnet_b_enabled', False)
    else:
        podnet_b_enabled = False
        

    # Find the host_status
    instanciated_infra = get_instanciated_infra()
    instanciated_metadata = get_instanciated_metadata()
    instanciated_blend = instanciated_metadata['config.json'].get('blend', 0)
    invert = get_test_bit_map('invert')

    if instanciated_blend == cop:
        if instanciated_infra['hostname'] == 'podnet-a':
            if cidata['mountable'] is True:
                if podnet_b_enabled is False:
                    host_status = cop_install_podnet_a
                    host_status_text = "cop_install_podnet_a"
                else:
                    host_status = cop_reinstall_podnet_a
                    host_status_text = "cop_reinstall_podnet_a"
            else:
                host_status = cop_validate_podnet_a
                host_status_text = "cop_validate_podnet_a"

        elif instanciated_infra['hostname'] == 'podnet-b':
            if cidata['mountable'] is True:
                host_status = cop_install_podnet_b
                host_status_text = "cop_install_podnet_b"
            else:
                host_status = cop_validate_podnet_b
                host_status_text = "cop_validate_podnet_b"

        elif instanciated_infra['hostname'] == 'appliance-a':
            if cidata['mountable'] is True:
                host_status = cop_install_appliance_a
                host_status_text = "cop_install_appliance_a"
            else:
                host_status = cop_validate_appliance_a
                host_status_text = "cop_validate_appliance_a"
        else:
                host_status = 0

    elif instanciated_blend == region:
        if instanciated_infra['hostname'] == 'podnet-a':
            if cidata['mountable'] is True:
                if podnet_b_enabled is False:
                    host_status = region_install_podnet_a
                    host_status_text = "region_install_podnet_a"
                else:
                    host_status = region_reinstall_podnet_a
                    host_status_text = "region_reinstall_podnet_a"
            else:
                host_status = region_validate_podnet_a
                host_status_text = "region_validate_podnet_a"

        elif instanciated_infra['hostname'] == 'podnet-b':
            if cidata['mountable'] is True:
                host_status = region_install_podnet_b
                host_status_text = "region_install_podnet_b"
            else:
                host_status = region_validate_podnet_b
                host_status_text = "region_validate_podnet_b"

        elif instanciated_infra['hostname'] == 'appliance-a':
            if cidata['mountable'] is True:
                host_status = region_install_appliance_a
                host_status_text = "region_install_appliance_a"
            else:
                host_status = region_validate_appliance_a
                host_status_text = "region_validate_appliance_a"
        else:
                host_status = 0

    elif instanciated_blend == copregion:
        if instanciated_infra['hostname'] == 'podnet-a':
            if cidata['mountable'] is True:
                if podnet_b_enabled is False:
                    host_status = copregion_install_podnet_a
                    host_status_text = "copregion_install_podnet_a"
                else:
                    host_status = copregion_reinstall_podnet_a
                    host_status_text = "copregion_reinstall_podnet_a"
            else:
                host_status = copregion_validate_podnet_a
                host_status_text = "copregion_validate_podnet_a"

        elif instanciated_infra['hostname'] == 'podnet-b':
            if cidata['mountable'] is True:
                host_status = copregion_install_podnet_b
                host_status_text = "copregion_install_podnet_b"
            else:
                host_status = copregion_validate_podnet_b
                host_status_text = "copregion_validate_podnet_b"

        elif instanciated_infra['hostname'] == 'appliance-a':
            if cidata['mountable'] is True:
                host_status = copregion_install_appliance_a
                host_status_text = "copregion_install_appliance_a"
            else:
                host_status = copregion_validate_appliance_a
                host_status_text = "copregion_validate_appliance_a"
        else:
                host_status = 0
    elif instanciated_blend == pat:
        if instanciated_infra['hostname'] == 'podnet-a':
            if cidata['mountable'] is True:
                if podnet_b_enabled is False:
                    host_status = pat_install_podnet_a
                    host_status_text = "pat_install_podnet_a"
                else:
                    host_status = pat_reinstall_podnet_a
                    host_status_text = "pat_reinstall_podnet_a"
            else:
                host_status = pat_validate_podnet_a
                host_status_text = "pat_validate_podnet_a"

        elif instanciated_infra['hostname'] == 'podnet-b':
            if cidata['mountable'] is True:
                host_status = pat_install_podnet_b
                host_status_text = "pat_install_podnet_b"
            else:
                host_status = pat_validate_podnet_b
                host_status_text = "pat_validate_podnet_b"

        elif instanciated_infra['hostname'] == 'appliance-a':
            if cidata['mountable'] is True:
                host_status = pat_install_appliance_a
                host_status_text = "pat_install_appliance_a"
            else:
                host_status = pat_validate_appliance_a
                host_status_text = "pat_validate_appliance_a"
        else:
                host_status = 0
    else:
        host_status = 0

    if host_status == 0:
        host_status_text = 'Unknown'
        fail_map = invert  # All ones representing all tests have failed
        update_fail_map(fail_map)
    
    insert_host_status(host_status, host_status_text)

    # Determine which maps to use based on host_status
    if host_status == cop_validate_podnet_a:
        warn = get_test_bit_map('cop_validate_podnet_a_warn')
        fail = get_test_bit_map('cop_validate_podnet_a_fail')
    elif host_status == cop_validate_podnet_b:
        warn = get_test_bit_map('cop_validate_podnet_b_warn')
        fail = get_test_bit_map('cop_validate_podnet_b_fail')
    elif host_status == cop_validate_appliance_a:
        warn = get_test_bit_map('cop_validate_appliance_a_warn')
        fail = get_test_bit_map('cop_validate_appliance_a_fail')
    elif host_status == cop_install_podnet_a:
        warn = get_test_bit_map('cop_install_podnet_a_warn')
        fail = get_test_bit_map('cop_install_podnet_a_fail')
    elif host_status == cop_install_podnet_b:
        warn = get_test_bit_map('cop_install_podnet_b_warn')
        fail = get_test_bit_map('cop_install_podnet_b_fail')
    elif host_status == cop_install_appliance_a:
        warn = get_test_bit_map('cop_install_appliance_a_warn')
        fail = get_test_bit_map('cop_install_appliance_a_fail')
    elif host_status == cop_reinstall_podnet_a:
        warn = get_test_bit_map('cop_reinstall_podnet_a_warn')
        fail = get_test_bit_map('cop_reinstall_podnet_a_fail')
    elif host_status == region_validate_podnet_a:
        warn = get_test_bit_map('region_validate_podnet_a_warn')
        fail = get_test_bit_map('region_validate_podnet_a_fail')
    elif host_status == region_validate_podnet_b:
        warn = get_test_bit_map('region_validate_podnet_b_warn')
        fail = get_test_bit_map('region_validate_podnet_b_fail')
    elif host_status == region_validate_appliance_a:
        warn = get_test_bit_map('region_validate_appliance_a_warn')
        fail = get_test_bit_map('region_validate_appliance_a_fail')
    elif host_status == region_install_podnet_a:
        warn = get_test_bit_map('region_install_podnet_a_warn')
        fail = get_test_bit_map('region_install_podnet_a_fail')
    elif host_status == region_install_podnet_b:
        warn = get_test_bit_map('region_install_podnet_b_warn')
        fail = get_test_bit_map('region_install_podnet_b_fail')
    elif host_status == region_install_appliance_a:
        warn = get_test_bit_map('region_install_appliance_a_warn')
        fail = get_test_bit_map('region_install_appliance_a_fail')
    elif host_status == region_reinstall_podnet_a:
        warn = get_test_bit_map('region_reinstall_podnet_a_warn')
        fail = get_test_bit_map('region_reinstall_podnet_a_fail')
    elif host_status == copregion_validate_podnet_a:
        warn = get_test_bit_map('copregion_validate_podnet_a_warn')
        fail = get_test_bit_map('copregion_validate_podnet_a_fail')
    elif host_status == copregion_validate_podnet_b:
        warn = get_test_bit_map('copregion_validate_podnet_b_warn')
        fail = get_test_bit_map('copregion_validate_podnet_b_fail')
    elif host_status == copregion_validate_appliance_a:
        warn = get_test_bit_map('copregion_validate_appliance_a_warn')
        fail = get_test_bit_map('copregion_validate_appliance_a_fail')
    elif host_status == copregion_install_podnet_a:
        warn = get_test_bit_map('copregion_install_podnet_a_warn')
        fail = get_test_bit_map('copregion_install_podnet_a_fail')
    elif host_status == copregion_install_podnet_b:
        warn = get_test_bit_map('copregion_install_podnet_b_warn')
        fail = get_test_bit_map('copregion_install_podnet_b_fail')
    elif host_status == copregion_install_appliance_a:
        warn = get_test_bit_map('copregion_install_appliance_a_warn')
        fail = get_test_bit_map('copregion_install_appliance_a_fail')
    elif host_status == copregion_reinstall_podnet_a:
        warn = get_test_bit_map('copregion_reinstall_podnet_a_warn')
        fail = get_test_bit_map('copregion_reinstall_podnet_a_fail')
    elif host_status == pat_validate_podnet_a:
        warn = get_test_bit_map('pat_validate_podnet_a_warn')
        fail = get_test_bit_map('pat_validate_podnet_a_fail')
    elif host_status == pat_validate_podnet_b:
        warn = get_test_bit_map('pat_validate_podnet_b_warn')
        fail = get_test_bit_map('pat_validate_podnet_b_fail')
    elif host_status == pat_validate_appliance_a:
        warn = get_test_bit_map('pat_validate_appliance_a_warn')
        fail = get_test_bit_map('pat_validate_appliance_a_fail')
    elif host_status == pat_install_podnet_a:
        warn = get_test_bit_map('pat_install_podnet_a_warn')
        fail = get_test_bit_map('pat_install_podnet_a_fail')
    elif host_status == pat_install_podnet_b:
        warn = get_test_bit_map('pat_install_podnet_b_warn')
        fail = get_test_bit_map('pat_install_podnet_b_fail')
    elif host_status == pat_install_appliance_a:
        warn = get_test_bit_map('pat_install_appliance_a_warn')
        fail = get_test_bit_map('pat_install_appliance_a_fail')
    elif host_status == pat_reinstall_podnet_a:
        warn = get_test_bit_map('pat_reinstall_podnet_a_warn')
        fail = get_test_bit_map('pat_reinstall_podnet_a_fail')
    else:
        warn = 0b0
        fail = 0b0
    
    ignore = (warn | fail) ^ invert

    update_test_levels(fail, ignore, warn)

    ##########################################################################
    #      Run the Tests   (test_id, optional test value)                    #
    ##########################################################################

    hard_core_coun(0, 20)
    hard_ram_count(1, 8)
    hard_stor_coun(2, 300)
    hard_pprt_coun(3, 5)
    hard_aprt_coun(4, 1)
    hard_publ_oper(5)
    hard_publ_carr(6)
    hard_publ_ethn(7)
    hard_mgmt_oper(8)
    hard_mgmt_carr(9)
    hard_mgmt_ethn(10)
    hard__ha__oper(11)
    hard__ha__carr(12)
    hard__ha__ethn(13)
    hard_priv_oper(14)
    hard_priv_carr(15)
    hard_priv_ethn(16)
    hard_intr_oper(17)
    hard_intr_carr(18)
    hard_intr_ethn(19)
    config_matches(20)
    inst_conf_pnum(21)
    inst_conf_pnam(22)
    inst_conf_blen(23, [cop, region, copregion, pat])
    inst_conf_aena(24)
    inst_conf_aenb(25)
    inst_conf_bena(26)
    inst_conf_benb(27)
    inst_conf_aben(28)
    inst_conf_4lvr(29)
    inst_conf_4lvm(30)
    inst_conf_4cva(31)
    inst_conf_4cpe(32)
    inst_conf_4pva(33)
    inst_conf__4pe(34)
    inst_conf_4pvc(35)
    inst_conf_6lvr(36)
    inst_conf_6lvm(37)
    inst_conf_6cva(38)
    inst_conf_6cpe(39)
    inst_conf_6pva(40)
    inst_conf__6pe(41)
    inst_conf_6pvc(42)
    inst_conf_4pmv(43)
    inst_conf_4pmm(44)
    inst_conf_6pmv(45)
    inst_conf_6pmm(46)
    inst_conf_dnss(47)
    inst_conf_pras(48)
    inst_conf_pv6s(49)
    inst_conf_cmon(50)
    ping_ipv4___pe(51)
    ping_ipv4__cpe(52)
    ping_ipv4_8888(53)
    ping_ipv6___pe(54)
    ping_ipv6__cpe(55)
    ping_ipv6_8888(56)
    dnsr_ipv4_ggle(57)
    dnsr_ipv6_ggle(58)

    pass_map, warn_map, fail_map, test_result = get_test_results()
    host_status, host_status_text = get_host_details()

    return host_status, host_status_text, pass_map, warn_map, fail_map, test_result
