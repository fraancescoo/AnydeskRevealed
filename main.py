import psutil
from scapy.all import sniff, IP

def get_anydesk_connections():
    anydesk_conns = []
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] and 'anydesk.exe' in proc.info['name'].lower():
            try:
                conns = proc.connections(kind='inet')
                anydesk_conns.extend(conns)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
    return anydesk_conns

def print_anydesk_conns(conns):
    for conn in conns:
        laddr = conn.laddr
        raddr = conn.raddr
        status = conn.status
        print(f"\n\x1b[38;2;255;0;0mNEW CONNECTION CAPTURED:\n\x1b[38;2;192;192;192m- Local address: \x1b[38;2;255;0;0m{laddr}\n\x1b[38;2;192;192;192m- Remote address: \x1b[38;2;255;0;0m{raddr}\n\x1b[38;2;192;192;192m- Status: \x1b[38;2;255;0;0m{status}\n\x1b[0m")

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        for conn in anydesk_conns:
            if conn.raddr:
                if ip_layer.src == conn.raddr.ip or ip_layer.dst == conn.raddr.ip:
                    print(f"\n\x1b[38;2;255;0;0mNEW PACKET CAPTURED:\n\x1b[38;2;192;192;192m- Source: \x1b[38;2;255;0;0m{ip_layer.src}\n\x1b[38;2;192;192;192m- Destination: \x1b[38;2;255;0;0m{ip_layer.dst}\n\x1b[0m")

if __name__ == "__main__":
    print('''\x1b[38;2;255;0;0m
           ,ggg,                                                                     ,ggggggggggg,                                                                            
          dP""8I                                    8I                     ,dPYb,   dP"""88""""""Y8,                                               ,dPYb,                  8I 
         dP   88                                    8I                     IP'`Yb   Yb,  88      `8b                                               IP'`Yb                  8I 
        dP    88                                    8I                     I8  8I    `"  88      ,8P                                               I8  8I                  8I 
       ,8'    88                                    8I                     I8  8bgg,     88aaaad8P"                                                I8  8'                  8I 
       d88888888    ,ggg,,ggg,   gg     gg    ,gggg,8I   ,ggg,     ,g,     I8 dP" "8     88""""Yb,     ,ggg,      ggg    gg    ,ggg,     ,gggg,gg  I8 dP   ,ggg,     ,gggg,8I 
 __   ,8"     88   ,8" "8P" "8,  I8     8I   dP"  "Y8I  i8" "8i   ,8'8,    I8d8bggP"     88     "8b   i8" "8i    d8"Yb   88bg i8" "8i   dP"  "Y8I  I8dP   i8" "8i   dP"  "Y8I 
dP"  ,8P      Y8   I8   8I   8I  I8,   ,8I  i8'    ,8I  I8, ,8I  ,8'  Yb   I8P' "Yb,     88      `8i  I8, ,8I   dP  I8   8I   I8, ,8I  i8'    ,8I  I8P    I8, ,8I  i8'    ,8I 
Yb,_,dP       `8b,,dP   8I   Yb,,d8b, ,d8I ,d8,   ,d8b, `YbadP' ,8'_   8) ,d8    `Yb,    88       Yb, `YbadP' ,dP   I8, ,8I   `YbadP' ,d8,   ,d8b,,d8b,_  `YbadP' ,d8,   ,d8b,
 "Y8P"         `Y88P'   8I   `Y8P""Y88P"888P"Y8888P"`Y8888P"Y888P' "YY8P8P88P      Y8    88        Y8888P"Y8888"     "Y8P"   888P"Y888P"Y8888P"`Y88P'"Y88888P"Y888P"Y8888P"`Y8
                                      ,d8I'                                                                                                                                   
                                    ,dP'8I                                                                                                                                    
                                   ,8"  8I                                                                                                                                    
                                   I8   8I                                                                                                                                    
                                   `8, ,8I                                                                                                                                    
                                    `Y8P"                                                                                                                                     

                                                                \x1b[38;2;204;0;0mhttps://github.com/Fraancescoo/AnydeskRevealed
\x1b[0m''')
    print("\x1b[38;2;192;192;192mMonitoring Anydesk.exe connections...\x1b[38;2;204;0;0m")

    anydesk_conns = get_anydesk_connections()
    print('\x1b[0m')
    
    if not anydesk_conns:
        print("\x1b[38;2;204;0;0mNo active Anydesk connections found.\x1b[0m")
    else:
        print_anydesk_conns(anydesk_conns)

        print("\x1b[38;2;192;192;192mSniffing network packets... Press Ctrl+C to stop.\x1b[0m")
        sniff(filter="tcp", prn=packet_callback, store=0)