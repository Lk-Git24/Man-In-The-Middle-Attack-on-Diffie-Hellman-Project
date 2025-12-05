# generate_rsa_keys.py
from Crypto.PublicKey import RSA

def generate_and_save(name_prefix="id"):
    key = RSA.generate(2048)
    priv = key.export_key()
    pub = key.publickey().export_key()
    with open(f"{name_prefix}_rsa_priv.pem", "wb") as f:
        f.write(priv)
    with open(f"{name_prefix}_rsa_pub.pem", "wb") as f:
        f.write(pub)
    print(f"Saved {name_prefix}_rsa_priv.pem and {name_prefix}_rsa_pub.pem")

if __name__ == "__main__":
    generate_and_save("eddie")   # or "venom"


