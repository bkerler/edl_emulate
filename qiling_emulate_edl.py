#!/usr/bin/env python3
#QC EDL Loader emulator via Qiling
#(c) B.Kerler 2020, licenced under MIT

import sys, os
sys.path.append("..")
from qiling import *
from unicorn import *
from unicorn.arm64_const import *
import logging
from struct import pack, unpack
import time

def replace_function(ql,addr,callback):
    def runcode(ql):
        ret=callback(ql)
        ql.reg.x0=ret
        ql.reg.pc=ql.reg.x30 #lr
    ql.hook_address(runcode,addr)

def hook_mem_invalid(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    if access == UC_MEM_WRITE:
        info=("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, pc, size, value))
    if access == UC_MEM_READ:
        info=("invalid READ of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH:
        info=("UC_MEM_FETCH of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_READ_UNMAPPED:
        info=("UC_MEM_READ_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_WRITE_UNMAPPED:
        info=("UC_MEM_WRITE_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH_UNMAPPED:
        info=("UC_MEM_FETCH_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_WRITE_PROT:
        info=("UC_MEM_WRITE_PROT of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH_PROT:
        info=("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_FETCH_PROT:
        info=("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    if access == UC_MEM_READ_AFTER:
        info=("UC_MEM_READ_AFTER of 0x%x at 0x%X, data size = %u" % (address, pc, size))
    print(info)
    return False

def main():
    ql=Qiling([os.path.join("loader","0000000000000000_bdaf51b59ba21d8a_FHPRG.bin")],rootfs=".",output="default")
    ql.gdb = "0.0.0.0:9999"
    ql.arch.enable_vfp()

    def devprg_time_usec(ql):
        current_milli_time = int(round(time.time() * 1000))
        ql.reg.x0 = current_milli_time
        print(f"Setting current timestamp as: {current_milli_time}")
        return current_milli_time

    def devprg_tx_blocking(ql):
        ptr = ql.reg.x0
        len = ql.reg.x1
        data = ql.mem.read(ptr, len)
        # args["X0"]=0x0
        # args["PC"]=0x148348A0
        print(f"\"{bytes(data)}\"")
        return 0

    ql.uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    replace_function(ql,0x148595A0,devprg_time_usec)   # Register 0xC221000
    replace_function(ql,0x1485C614,devprg_tx_blocking) # Function being used by UART in DP_LOGI

    ql.reg.sp=0x146B2000             # SP from main
    xml_buffer_addr=0x14684E80       # We extracted that from devprg_get_xml_buffer
    device_serial_addr=0x148A8A8C
    device_serial=pack("<Q",0x1337BABE)
    uart_data = b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<data>\n<nop /></data>\x00"
    ql.reg.x0=xml_buffer_addr
    ql.reg.x1=len(uart_data)
    ql.mem.write(xml_buffer_addr,uart_data)
    ql.mem.write(device_serial_addr,device_serial)
    handle_xml_addr=0x14857C94
    handle_xml_end=0x14857D4C
    ql.run(begin=handle_xml_addr,end=handle_xml_end)

if __name__=="__main__":
    main()