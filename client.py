#!/usr/bin/env python3
from Library.tcpclient import tcpclient

def main():
    tcp=tcpclient(1337)
    xmlcommand=b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><nop /></data>"
    print("Sending : "+xmlcommand.decode('utf-8'))
    resp=tcp.sendcommands([xmlcommand])
    print(resp.decode('utf-8'))

if __name__=="__main__":
    main()