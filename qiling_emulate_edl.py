#!/usr/bin/env python3
#QC EDL Loader emulator via Qiling
#(c) B.Kerler 2020, licenced under MIT

import sys, os
sys.path.append("..")
from qiling import *
from unicorn import *
from unicorn.arm64_const import *
import logging
from Library.utils import *
from struct import pack, unpack
import time

import socket
import threading
import queue

q = queue.Queue()
r = queue.Queue()

def run_server(name):
    global q
    global r
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('0.0.0.0', 1337)
    print('starting up on %s port %s' % server_address)
    sock.bind(server_address)
    sock.listen(1)
    while True:
        print('waiting for a connection')
        connection, client_address = sock.accept()
        try:
            print('connection from', client_address)
            while True:
                data = connection.recv(4096)
                if data:
                    print('received %s' % data)
                    predata=b""
                    while not r.empty():
                        predata+=r.get()
                        time.sleep(0.05)
                    q.put(data)
                    while r.empty():
                        time.sleep(0.05)
                    data=b""
                    while not b"response value" in data or not r.empty():
                        data+=r.get()
                        time.sleep(0.05)
                    connection.send(predata+data)
                    connection.close()
                    break
        except Exception as e:
            logging.error(str(e))

def replace_function(ql,addr,callback):
    def runcode(ql):
        ret=callback(ql)
        ql.reg.x0=ret
        ql.reg.pc=ql.reg.x30 #lr
    ql.hook_address(runcode,addr)

def hook_mem_read(uc,access,address,size,value,user_data):
    if address<0xF000000:
        pc = uc.reg_read(UC_ARM64_REG_PC)
        print("READ of 0x%x at 0x%X, data size = %u" % (address, pc, size))

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
    filename=os.path.join("loader",sys.argv[1])
    data = open(filename, "rb").read()
    elfheader = elf(data,filename)
    pt = patchtools()

    def get_handle_xml_func_addr(elfheader, data):
        addr=pt.find_binary(data, b"\xF8\x5F\xBC\xA9\xF6\x57\x01\xA9\xF4\x4F\x02\xA9\xFD\x7B\x03\xA9\xFD\xC3\x00\x91\xF4\x03\x01\xAA")
        start=elfheader.getvirtaddr(addr)
        endaddr=pt.find_binary(data,b"\xC0\x03\x5F\xD6",addr)
        end = elfheader.getvirtaddr(endaddr)
        return start,end

    def get_devprg_time_usec_func_addr(elfheader,data):
        addr=pt.find_binary(data, b"\x08\x00\x82\x52\x48\x84\xA1\x72\x0A\x01")
        return elfheader.getvirtaddr(addr)

    handle_xml_addr_start, handle_xml_addr_end=get_handle_xml_func_addr(elfheader, data)
    devprg_time_usec_addr=get_devprg_time_usec_func_addr(elfheader,data)
    print("Handle_XML start:       "+hex(handle_xml_addr_start))
    print("Handle_XML end:         "+hex(handle_xml_addr_end))
    print("devprg_time_usec start: "+hex(devprg_time_usec_addr)) #0x148595A0

    ql=Qiling([filename],rootfs=".",output="default")
    ql.gdb = "0.0.0.0:9999"
    ql.arch.enable_vfp()



    def devprg_time_usec(ql):
        current_milli_time = int(round(time.time() * 1000))
        ql.reg.x0 = current_milli_time
        print(f"Setting current timestamp as: {current_milli_time}")
        return current_milli_time

    def devprg_tx_blocking(ql):
        global r
        ptr = ql.reg.x0
        len = ql.reg.x1
        data = ql.mem.read(ptr, len)
        #print(f"\"{bytes(data)}\"")
        r.put(data)
        return 0

    size=0

    def devprg_rx_queue(ql):
        global size
        xml_buffer_addr = 0x14684E80  # We extracted that from devprg_get_xml_buffer
        while q.empty():
            time.sleep(0.05)
        devprg_buffer_in_use_addr=0x1468B280
        ql.mem.write(devprg_buffer_in_use_addr, pack("<Q", 0)) # We got that one from devprg_get_buffer_for_transfer
        uart_data=q.get()
        ql.mem.write(xml_buffer_addr, uart_data)
        size=len(uart_data)
        return 0

    def devprg_rx_queue_wait(ql):
        global size
        ql.mem.write(ql.reg.x0,pack("<Q",size))
        return 0

    def qhsusb_al_bulk_receive(ql):
        print(hex(ql.reg.x0))
        print(hex(ql.reg.x1))
        uart_data = b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<data>\n<nop /></data>\x00"
        xml_buffer_addr = 0x14684E80
        ql.mem.write(xml_buffer_addr,uart_data)
        ql.reg.x0=xml_buffer_addr
        ql.reg.x1=len(uart_data)
        return 0

    def devprg_target_init(ql):
        return 0

    def unknown(ql):
        return 0

    def boot_fastcall_tz(ql):
        X0=hex(ql.reg.x0)
        X1=hex(ql.reg.x1)
        X2=hex(ql.reg.x2)
        X3=hex(ql.reg.x3)
        X4=hex(ql.reg.x4)
        print(f"TZ SMC: X0:{X0} X1:{X1} X2:{X2} X3:{X3} X4:{X4}")
        return 0

    def boot_error_handler(ql):
        X0 = bytes(ql.mem.read(ql.reg.x0,18).rstrip(b"\x00")).decode('utf-8')
        X1 = hex(ql.reg.x1)
        print(f"boot_error_handler: X0:{X0} X1:{X1}")
        return 0

    ql.uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    ql.uc.hook_add(UC_HOOK_MEM_READ,hook_mem_read)
    replace_function(ql,devprg_time_usec_addr,devprg_time_usec)   # Register 0xC221000
    replace_function(ql,0x1485BCC0,devprg_target_init)
    replace_function(ql,0x1485C614,devprg_tx_blocking) # Function being used by UART in DP_LOGI
    replace_function(ql,0x1485C05C,devprg_rx_queue)
    replace_function(ql,0x1485C384,devprg_rx_queue_wait)
    #replace_function(ql,0x14879744,qhsusb_al_bulk_receive)

    replace_function(ql,0x146AE000,boot_fastcall_tz)
    replace_function(ql,0x1485E20C,boot_error_handler)
    ql.reg.sp=0x146B2000             # SP from main

    device_serial_addr=0x148A8A8C
    device_serial=pack("<Q",0x1337BABE)

    #ql.reg.x1=len(uart_data)
    ql.mem.map(0x1fc8000,1024) #0x1fc8004 #UART
    ql.mem.map(0xc221000,1024) #0xc221000
    ql.mem.write(0xc221000,pack("<Q",int(round(time.time() * 1000))))
    ql.mem.write(device_serial_addr,device_serial)

    x = threading.Thread(target=run_server, args=(1,), daemon=True)
    x.start()
    #q.put(b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<data>\n<nop /></data>\x00")
    ql.run(begin=0x14857DAC,end=0x14857E44)

if __name__=="__main__":
    main()