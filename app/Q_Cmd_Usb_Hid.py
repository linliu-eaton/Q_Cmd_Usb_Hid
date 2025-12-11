# coding: utf-8
import os.path
import time

import configparser
import logging

import hid
from ctypes import *


__all__ = ["q_cmd_hid"]

# usb
_USB_vid = 0x0000
_USB_pid = 0x0000
# qcmd
_QCMD_rspTimeoutSec = 2
_QCMD_cmdIntervalMs = 100
_QCMD_loopTimes = 1
_QCMD_enableChkRsp = False
_QCMD_cmdList = ''
_QCMD_rspList = ''
# logging
_LOG_enableLog = False
_LOG_logDir = ''

HID_DEV = None    # dev handler
_CMD_LIST = []
_RSP_LIST = []


# log config --------------------------
def _log_init():
    if _LOG_enableLog is False:
        return

    log_file = os.path.join(_LOG_logDir, "q_hid_log.log")
    log_file_abs = os.path.abspath(log_file)
    print("Log file: " + str(log_file_abs))
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename=log_file_abs,
                        filemode='a')


def _log_debug(msg, *args, **kwargs):
    if _LOG_enableLog is False:
        return
    logging.debug(msg, *args, **kwargs)


def _log_info(msg, *args, **kwargs):
    if _LOG_enableLog is False:
        return
    logging.info(msg, *args, **kwargs)


def _log_warn(msg, *args, **kwargs):
    if _LOG_enableLog is False:
        return
    logging.warning(msg, *args, **kwargs)


def _log_critical(msg, *args, **kwargs):
    if _LOG_enableLog is False:
        return
    logging.critical(msg, *args, **kwargs)


# config parse --------------------------
def _show_config():
    print("_USB_vid=" + str(hex(_USB_vid)))
    print("_USB_pid=" + str(hex(_USB_pid)))
    print("_QCMD_rspTimeoutSec=" + str(_QCMD_rspTimeoutSec))
    print("_QCMD_cmdIntervalMs=" + str(_QCMD_cmdIntervalMs))
    print("_QCMD_loopTimes=" + str(_QCMD_loopTimes))
    print("_QCMD_enableChkRsp=" + str(_QCMD_enableChkRsp))
    print("_QCMD_cmdList=" + str(_QCMD_cmdList))
    print("_QCMD_rspList=" + str(_QCMD_rspList))
    print("_LOG_enableLog=" + str(_LOG_enableLog))
    print("_LOG_logDir=" + str(_LOG_logDir))

    _log_info("_USB_vid=" + str(_USB_vid))
    _log_info("_USB_pid=" + str(_USB_pid))
    _log_info("_QCMD_rspTimeoutSec=" + str(_QCMD_rspTimeoutSec))
    _log_info("_QCMD_cmdIntervalMs=" + str(_QCMD_cmdIntervalMs))
    _log_info("_QCMD_loopTimes=" + str(_QCMD_loopTimes))
    _log_info("_QCMD_enableChkRsp=" + str(_QCMD_enableChkRsp))
    _log_info("_QCMD_cmdList=" + str(_QCMD_cmdList))
    _log_info("_QCMD_rspList=" + str(_QCMD_rspList))
    _log_info("_LOG_enableLog=" + str(_LOG_enableLog))
    _log_info("_LOG_logDir=" + str(_LOG_logDir))


def _config_parse():
    config_path = os.path.join(os.path.dirname(__file__), 'Q_Cmd_Usb_Hid.ini')
    config = configparser.ConfigParser()
    config.read(config_path, encoding='utf-8')

    global _USB_vid
    global _USB_pid

    global _QCMD_rspTimeoutSec
    global _QCMD_cmdIntervalMs
    global _QCMD_loopTimes
    global _QCMD_enableChkRsp
    global _QCMD_cmdList
    global _QCMD_rspList

    global _LOG_enableLog
    global _LOG_logDir

    # com
    _USB_vid = config.get('usb', 'vid')
    _USB_vid = int(_USB_vid, 16)
    _USB_pid = config.get('usb', 'pid')
    _USB_pid = int(_USB_pid, 16)

    # qcmd
    _QCMD_rspTimeoutSec = config.getint('qcmd', 'rspTimeoutSec')
    _QCMD_cmdIntervalMs = config.getint('qcmd', 'cmdIntervalMs')
    _QCMD_loopTimes = config.getint('qcmd', 'loopTimes')
    _QCMD_enableChkRsp = config.getboolean('qcmd', 'enableChkRsp')
    _QCMD_cmdList = config.get('qcmd', 'cmdList')
    if _QCMD_cmdList == '':
        raise Exception('Not config commands!')
    _QCMD_rspList = config.get('qcmd', 'rspList')
    if (_QCMD_enableChkRsp is True) and (_QCMD_rspList == ''):
        raise Exception("Check response enabled but no response list configured!")

    # log
    _LOG_enableLog = config.getboolean('log', 'enableLog')
    _LOG_logDir = config.get('log', 'logDir')
    if (_LOG_enableLog is True) and (_LOG_logDir == ''):
        raise Exception("Log enabled but no log file configured!")
    valid_dir = (os.path.isdir(_LOG_logDir)) and (os.access(_LOG_logDir, os.W_OK))
    if (_LOG_enableLog is True) and (not valid_dir):
        raise Exception("Log enabled but log file is invalid!")

    print("Parse config file success......")
    if _LOG_enableLog:
        _log_init()
    _log_info("Parse config file success......")

    _show_config()


def _config_to_char_list(conf_str: str) -> list:
    """return type: [['Q', '1', ''\r], ['F', 'W', 'V', '\r']]"""
    conf_list = []
    conf_str = conf_str.strip()
    if conf_str == '':
        return conf_list

    cmd_lst = conf_str.split(',')
    for cmd in cmd_lst:
        lst = []
        cmd = cmd.strip()
        if cmd == '':
            conf_list.append(lst)
            continue
        for s in cmd:
            lst.append(ord(s))
        lst.append(0x0D)
        conf_list.append(lst)
    return conf_list


def _get_cmd_ascii_list():
    global _CMD_LIST
    _CMD_LIST = _config_to_char_list(_QCMD_cmdList)
    print("CMD_LIST:" + str(_CMD_LIST))
    _log_info("CMD_LIST:" + str(_CMD_LIST))


def _get_rsp_str_list():
    """result type: [''Q1\r, 'FWV\r']"""
    global _QCMD_rspList
    global _RSP_LIST

    conf_str = _QCMD_rspList
    conf_str = conf_str.strip()
    if conf_str == '':
        _RSP_LIST.append('')
    else:
        _RSP_LIST = conf_str.split(',')

    if (_QCMD_enableChkRsp is True) and (len(_CMD_LIST) != len(_RSP_LIST)):
        raise Exception('Unmatched command and response count!')
    print("RSP_LIST:" + str(_RSP_LIST))
    _log_info("RSP_LIST:" + str(_RSP_LIST))


# usb hid ------------------------------------------------------
def enum_info(vendor=0, product=0, is_show=1):
    if is_show == 0:
        return
    dev = hid.enumerate(vid=vendor, pid=product)
    dev = dev[0]
    print("--------------USB Device Info--------------")
    _log_info("--------------USB Device Info--------------")
    print("path: " + str(dev['path']))
    _log_info("path: " + str(dev['path']))
    print("vendor_id: " + hex(dev['vendor_id']))
    _log_info("vendor_id: " + hex(dev['vendor_id']))
    print("product_id: " + hex(dev['product_id']))
    _log_info("product_id: " + hex(dev['product_id']))
    print("manufacturer_string: " + str(dev['manufacturer_string']))
    _log_info("manufacturer_string: " + str(dev['manufacturer_string']))
    print("product_string: " + str(dev['product_string']))
    _log_info("product_string: " + str(dev['product_string']))
    print("-----------------------------\n")
    _log_info("-----------------------------\n")


def hid_init(vid, pid, is_show):
    global HID_DEV
    if HID_DEV is not None:
        HID_DEV.close()
    HID_DEV = hid.Device(vid, pid)

    if is_show == 0:
        return
    _log_info("-----------------------------")
    _log_info("manufacturer: " + str(HID_DEV.manufacturer))
    _log_info("product: " + str(HID_DEV.product))
    _log_info("-----------------------------")
    print("-----------------------------")
    print("manufacturer: " + str(HID_DEV.manufacturer))
    print("product: " + str(HID_DEV.product))
    print("-----------------------------")


def hid_close():
    global HID_DEV
    if HID_DEV is not None:
        HID_DEV.close()


def hid_set_report(data: list):
    global HID_DEV
    assert HID_DEV is not None

    data1 = bytearray(data)
    buf = create_string_buffer(len(data1))
    for i in range(len(data1)):
        buf[i] = data1[i]
    result = HID_DEV.write(buf)
    return result


def hid_get_report(report_id, size):
    global HID_DEV
    assert HID_DEV is not None

    result = HID_DEV.get_input_report(report_id, size)
    return result


def hid_recv_rsp(timeout_sec: int):
    global HID_DEV
    if timeout_sec <= 0:
        timeout_sec = 10  # 10s as default

    max_endpoint_size = 65
    rst = HID_DEV.read(max_endpoint_size, _QCMD_rspTimeoutSec * 1000)
    result = ''
    for r in rst:
        if r == 0x0D:
            return result
        result += chr(r)
    return result


def _cmd_rsp_check(cmd: list, idx: int, result: str):
    if _QCMD_enableChkRsp is False:
        return

    if _RSP_LIST[idx] == '_':
        print(str(cmd) + "(idx:" + str(idx) + ") " + "rsp check Ignored!")
        _log_info(str(cmd) + "(idx:" + str(idx) + ") " + "rsp check Ignored!")
        return

    if len(result) <= 1:
        print(str(cmd) + "(idx:" + str(idx) + ") " + "rsp check Failed, blank response!")
        _log_info(str(cmd) + "(idx:" + str(idx) + ") " + "rsp check Failed, blank response!")
        return

    if len(_RSP_LIST) < (idx + 1):
        print(str(cmd) + "(idx:" + str(idx) + ") " + "rsp check Failed, rsp config error!")
        _log_info(str(cmd) + "(idx:" + str(idx) + ") " + "rsp check Failed, rsp config error!")
        return

    if _RSP_LIST[idx] != result:
        print(str(cmd) + "(idx:" + str(idx) + ") " + "rsp check Failed!")
        _log_info(str(cmd) + "(idx:" + str(idx) + ") " + "rsp check Failed!")
        return

    print(str(cmd) + "(idx:" + str(idx) + ") " + "rsp check Succeed!")
    _log_info(str(cmd) + "(idx:" + str(idx) + ") " + "rsp check Succeed!")


def timecost(func):
    def wrapper():
        start_time = time.time()
        func()
        end_time = time.time()
        time_cost = end_time - start_time
        print("------------------------------------\n", "time_cost = ", str(time_cost), " second(s)")
        _log_info("------------------------------------\ntime_cost = " + str(time_cost) + " second(s)")
    return wrapper


@timecost
def q_cmd_hid():
    # config file
    try:
        _config_parse()
        _get_cmd_ascii_list()
        _get_rsp_str_list()
    except Exception as e:
        print("------Exception when parse config ", e)
        _log_info("------Exception when parse config ",  e)
        return

    # hid init
    try:
        hid_init(vid=_USB_vid, pid=_USB_pid, is_show=1)
        time.sleep(0.5)
        enum_info(vendor=_USB_vid, product=_USB_pid, is_show=1)
    except Exception as e:
        print("------Exception when init hid ", e)
        _log_info("------Exception when init hid ",  e)
        return

    print("usb hid communication is ready......")
    _log_info("usb hid communication is ready......")
    try:
        for loop in range(_QCMD_loopTimes):
            print("loop: " + str(loop + 1))
            _log_info("loop: " + str(loop + 1))
            for idx, cmd in enumerate(_CMD_LIST):
                if _QCMD_cmdIntervalMs > 0:
                    time.sleep(_QCMD_cmdIntervalMs/1000)
                try:
                    print("Send cmd: " + str(cmd))
                    _log_info("Send cmd: " + str(cmd))
                    cmd1 = cmd.copy()
                    cmd1.insert(0, 0)
                    hid_set_report(cmd1)

                    result = hid_recv_rsp(_QCMD_rspTimeoutSec)
                    print("Recv response: " + str(result))
                    _log_info("Recv response: " + str(result))

                    _cmd_rsp_check(cmd, idx, result)
                except Exception as e:
                    print("------Exception when send ", str(cmd), e)
                    _log_info("------Exception when send ", str(cmd), e)

    except Exception as e:
        print("------Exception in loop: ", e)
        _log_info("------Exception in loop: ",  e)
    hid_close()


if __name__ == "__main__":
    q_cmd_hid()

