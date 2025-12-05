# run.py
#!/usr/bin/env python3

import threading
import sys
import json
import base64
import network
from diffie_hellman import DiffieHellman
from crypto_protocol import CryptoProtocol
from crypto_sign import load_private_key, load_public_key, sign_bytes, verify_bytes, b64encode, b64decode
from Crypto.Random import get_random_bytes
import os

# استخدمها اذا دخلتي باراميترات غلط
def usage():
    print("Usage:")
    print("  Server: " + sys.argv[0] + " port")
    print("  Client: " + sys.argv[0] + " ip port")
    sys.exit()

if not (len(sys.argv) == 2 or len(sys.argv) == 3):
    usage()

conn = network.Connection()

def get_line():
    line = None
    while line is None:
        line = conn.recv()
    return line

# يسوي باكيت موقّع
def build_signed_packet(info, priv_key):
    json_bytes = json.dumps(info, sort_keys=True, separators=(',', ':')).encode()
    sig = sign_bytes(priv_key, json_bytes)
    info['signature'] = b64encode(sig)
    return json.dumps(info)

# التحقق من التوقيع
def verify_signed_packet(txt, peer_pub):
    data = json.loads(txt)
    sig = b64decode(data.get('signature', ''))
    tmp = dict(data)
    if 'signature' in tmp:
        tmp.pop('signature')
    msg = json.dumps(tmp, sort_keys=True, separators=(',', ':')).encode()
    ok = verify_bytes(peer_pub, msg, sig)
    return tmp, ok

# يخزن البروتوكول بعد الـ DH
crypto_protocol = None

def send_message(text):
    if crypto_protocol:
        conn.send_bytes(crypto_protocol.encrypt(text))
    else:
        print("crypto not ready")
        sys.exit(1)

# GUI
class GUIThread(threading.Thread):
    def __init__(self, title):
        threading.Thread.__init__(self)
        self.title = title

    def run(self):
        import gui
        gui.set_send_message_callback(send_message)
        gui.start(self.title)

# ================= SERVER =================

if len(sys.argv) == 2:
    # فتح منفذ
    try:
        conn.listen(int(sys.argv[1]))
    except:
        print("Could not open port:", sys.argv[1])
        sys.exit()

    # تحديد الهوية حسب وجود الملفات
    if os.path.exists("venom_rsa_priv.pem"):
        priv = load_private_key("venom_rsa_priv.pem")
        peer_pub = load_public_key("eddie_rsa_pub.pem")
        my_name = "Venom (Server)"
    else:
        priv = load_private_key("eddie_rsa_priv.pem")
        peer_pub = load_public_key("venom_rsa_pub.pem")
        my_name = "Eddie (Server)"

    dh = DiffieHellman()
    p, g, A = dh.generate_public_broadcast()
    salt = get_random_bytes(16)

    packet = {
        "type": "DH",
        "p": str(p),
        "g": str(g),
        "value": str(A),
        "salt": base64.b64encode(salt).decode(),
        "sender": my_name
    }

    conn.send(build_signed_packet(packet, priv))

    # استقبل B
    line = get_line()
    info, ok = verify_signed_packet(line, peer_pub)
    if not ok:
        print("Signature check failed (client).")
        sys.exit()

    B = int(info['value'])
    peer_salt = base64.b64decode(info['salt'])

    crypto_protocol = CryptoProtocol(dh.get_shared_secret(B), salt)

    GUIThread(my_name).start()

# ================= CLIENT =================

else:
    try:
        conn.connect(sys.argv[1], int(sys.argv[2]))
    except:
        print("Connection failed.")
        sys.exit()

    if os.path.exists("eddie_rsa_priv.pem"):
        priv = load_private_key("eddie_rsa_priv.pem")
        peer_pub = load_public_key("venom_rsa_pub.pem")
        my_name = "Eddie (Client)"
    else:
        priv = load_private_key("venom_rsa_priv.pem")
        peer_pub = load_public_key("eddie_rsa_pub.pem")
        my_name = "Venom (Client)"

    line = get_line()
    info, ok = verify_signed_packet(line, peer_pub)
    if not ok:
        print("Signature check failed (server).")
        sys.exit()

    p = int(info['p'])
    g = int(info['g'])
    A = int(info['value'])
    server_salt = base64.b64decode(info['salt'])

    dh = DiffieHellman(p, g)
    _, _, B = dh.generate_public_broadcast()

    salt = get_random_bytes(16)

    packet = {
        "type": "DH",
        "value": str(B),
        "salt": base64.b64encode(salt).decode(),
        "sender": my_name
    }

    conn.send(build_signed_packet(packet, priv))

    crypto_protocol = CryptoProtocol(dh.get_shared_secret(A), server_salt)

    GUIThread(my_name).start()

# ================= RECEIVE LOOP =================

while True:
    data = conn.recv_bytes()
    if data:
        import gui
        try:
            txt = crypto_protocol.decrypt(data)
        except:
            txt = "[ERROR: Could not decrypt]"
        gui.add_new_text("[Other] " + txt)
    else:
        break
