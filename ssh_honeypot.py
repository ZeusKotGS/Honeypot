# Libaries
import logging
from logging.handlers import RotatingFileHandler #set file to log to
import socket
import paramiko
import threading
# Constants
logging_format = logging.Formatter('%(message)s') #format
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

host_key = 'server.key'

#Loggers & Logging Files
funnel_logger = logging.getLogger('FunnelLogger') #capture passwords, IPs
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5) #set logging file
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler) #add logging file

creds_logger = logging.getLogger('FunnelLogger') #capture passwords, IPs
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5) #set logging file
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(funnel_handler) #add logging file

# Emulated Shell

def emulated_shell(channel, client_ip): #fake shell
    #way of communicating over SSH
    channel.send(b'corporate-jumpbox2$ ')
    command = b"" #listening...
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()

        command += char

        if char == b'\r':
            if command.strip() == b'exit':
                response = b'\n Goodbye!\n'
                channel.close()
            elif command.strip() == b'pwd':
                response = b'\n\\' + b'\\usr\\local' + b'\r\n'
            elif command.strip() == b'whoami':
                response = b'\n' + b'corpuser1' + b'\r\n'
            elif command.strip() == b'ls':
                response = b'\n' + b'jumpbox1.conf' + b'\r\n'
            elif command.strip() == b'cat jumpbox1.conf':
                response = b'\n' + b"Go to deeboodah.com." + b'\r\n'
            else:
                response = b'\n' + bytes(command.strip()) + b'\r\n'

        channel.send(response)
        channel.send(b'corporate-jumpbox2$ ')
        command = b""

# SSH Server + Sockets

class Server(paramiko.ServerInterface): 

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        
    def get_allowed_auth(self):
        return "password"
    
    def check_auth_password(self, username, password):
        if self.input_username is not None and self.input_password is not None:
            if username == 'username' and password == 'password':
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True
    
def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")

    try:
    
        transport = paramiko.Transport() #handling low-level ssh sessions
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)

        transport.start_server(server=server)

        channel = transport.accept(100) #waits for client to open a channel. 100 milliseconds for request
        if channel is None:
            print("No channel was opened.")

        standard_banner = "Welcome to Ubuntu 22.04 LTS!\r\n\r\n"
        channel.send(standard_banner)
        emulated_shell(channel, client_ip=client_ip)

    except Exception as error:
        
        print(error)
        print("!!! Error !!!")


    finally:
        
        try:
            transport.close()
        except Exception as error:
            print(error)
            print("!!! Error !!!")
        client.close()

#Provision SSH-based Honeypot

def honeypot(address, port, username, password): #main function
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100) #max 100 connections
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()

        except Exception as error:
            print(error)
