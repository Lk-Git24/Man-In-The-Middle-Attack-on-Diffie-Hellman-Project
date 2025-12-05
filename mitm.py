#mitm.py
#!/usr/bin/env python3
import sys
import json
import base64
import threading
import network
from crypto_sign import load_public_key, verify_bytes, b64decode
from Crypto.Random import get_random_bytes

def usage():
    print("Usage: python mitm.py server_ip server_port client_port")
    print("Example: python mitm.py 127.0.0.1 12345 9001")
    sys.exit()

if len(sys.argv) != 4:
    usage()

server_ip = sys.argv[1]
server_port = int(sys.argv[2])
client_port = int(sys.argv[3])

# conn_server connects to the real server
conn_server = network.Connection()
# conn_client listens for the real client
conn_client = network.Connection()

try:
    conn_client.listen(client_port)
except Exception as e:
    print("Unable to open client listening port", client_port, e)
    sys.exit()

try:
    conn_server.connect(server_ip, server_port)
except Exception as e:
    print("Unable to connect to server", server_ip, server_port, e)
    sys.exit()

# helper to read a non-empty line (text)
def get_line(conn):
    line = None
    while line is None:
        line = conn.recv()
    return line

# Load public keys (Mitm only needs public keys to verify; it should NOT have private keys)
# Make sure these files exist in mitm's folder (eddie_rsa_pub.pem, venom_rsa_pub.pem)
eddie_pub = None
venom_pub = None
try:
    eddie_pub = load_public_key("eddie_rsa_pub.pem")
except Exception:
    pass
try:
    venom_pub = load_public_key("venom_rsa_pub.pem")
except Exception:
    pass

def get_pub_for_sender(sender_name):
    if sender_name is None:
        return None
    if sender_name.lower().startswith("eddie") and eddie_pub:
        return eddie_pub
    if sender_name.lower().startswith("venom") and venom_pub:
        return venom_pub
    return None

def verify_signed_json(text):
    """
    Return tuple (data_dict_without_signature, ok_bool)
    """
    try:
        data = json.loads(text)
        sender = data.get("sender")
        pub = get_pub_for_sender(sender)
        if pub is None:
            return data, False
        sig_b64 = data.get("signature", "")
        sig = b64decode(sig_b64)
        # rebuild canonical json without signature
        data_no_sig = dict(data)
        data_no_sig.pop("signature", None)
        canonical = json.dumps(data_no_sig, sort_keys=True, separators=(',', ':')).encode()
        ok = verify_bytes(pub, canonical, sig)
        return data_no_sig, ok
    except Exception as e:
        return None, False

# --- Handshake handling ---
# We expect the server to send a single JSON packet with p,g,value(A),salt
server_packet = get_line(conn_server)
print("[MITM] Received from server (raw):")
print(server_packet)

data_no_sig, ok = verify_signed_json(server_packet)
print(f"[MITM] Server signature valid? {ok}")
if data_no_sig is None:
    print("[MITM] Couldn't parse server packet as JSON. Forwarding raw.")
    conn_client.send(server_packet)
else:
    # show parsed fields
    print("[MITM] Server packet fields:", {k: data_no_sig.get(k) for k in ("type","p","g","value","salt","sender")})

    # Option 1: forward the packet intact (attack fails - secure)
    print("[MITM] Forwarding server packet unchanged to client (no tampering).")
    conn_client.send(json.dumps(dict(data_no_sig, signature= json.loads(server_packet).get("signature"))))

    # Option 2 (uncomment to test tampering): attempt to tamper value (this should break signature)
    # tampered = dict(data_no_sig)
    # try:
    #     tampered["value"] = str(int(tampered.get("value", "0")) + 1)
    # except:
    #     tampered["value"] = "0"
    # print("[MITM] Sending tampered packet to client (signature now invalid).")
    # conn_client.send(json.dumps(tampered))  # note: no valid signature attached -> receiver will reject

# Now receive client's B packet (also JSON signed)
client_packet = get_line(conn_client)
print("[MITM] Received from client (raw):")
print(client_packet)

data_no_sig_c, ok_c = verify_signed_json(client_packet)
print(f"[MITM] Client signature valid? {ok_c}")
if data_no_sig_c is None:
    print("[MITM] Couldn't parse client packet as JSON. Forwarding raw.")
    conn_server.send(client_packet)
else:
    print("[MITM] Client packet fields:", {k: data_no_sig_c.get(k) for k in ("type","value","salt","sender")})
    # Forward untouched to server
    conn_server.send(json.dumps(dict(data_no_sig_c, signature= json.loads(client_packet).get("signature"))))

# --- At this point handshake finished, both sides will derive keys.
print("[MITM] Handshake forwarded. Now proxying encrypted messages (cannot decrypt).")

# --- Proxy loop: forward encrypted bytes between client and server unchanged
def proxy_loop(src_conn, dst_conn, name):
    while True:
        b = src_conn.recv_bytes()
        if b:
            print(f"[MITM] Forwarding {len(b)} bytes ({name})")
            dst_conn.send_bytes(b)
        else:
            break

t = threading.Thread(target=proxy_loop, args=(conn_client, conn_server, "client->server"))
t.daemon = True
t.start()
proxy_loop(conn_server, conn_client, "server->client")
