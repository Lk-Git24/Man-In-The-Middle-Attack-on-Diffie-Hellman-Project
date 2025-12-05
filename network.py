#network.py
#!/usr/bin/env python3
import pwn
import base64
class Connection:
   def __init__(self):
       self.data_buffer = []
   def listen(self, port_no):
       l = pwn.listen(port_no)
       self.conn = l.wait_for_connection()
   def connect(self, ip, port_no):
       self.conn = pwn.remote(ip, port_no)
   def recv(self):
       try:
           raw = self.conn.recvline().strip()  # raw bytes
           if not raw:
               return None
           decoded_bytes = base64.b64decode(raw)
           return decoded_bytes.decode("utf-8")
       except EOFError:
           return None
   def recv_bytes(self):
       try:
           raw = self.conn.recvline().strip()
           if not raw:
               return None
           return base64.b64decode(raw)
       except EOFError:
           return None
   def send(self, data):
       byte_data = data.encode("utf-8")
       b64_encoded = base64.b64encode(byte_data)
       self.conn.send(b64_encoded + b"\n")
   def send_bytes(self, data_bytes):
       b64_encoded = base64.b64encode(data_bytes)
       self.conn.send(b64_encoded + b"\n")