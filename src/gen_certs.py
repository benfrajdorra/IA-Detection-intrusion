import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

os.makedirs("certs", exist_ok=True)
now = datetime.datetime.now(datetime.timezone.utc)
debut = now - datetime.timedelta(minutes=1)
fin = now + datetime.timedelta(days=365)


def nouvelle_cle():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def nom(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ecrire_pem(objet, chemin, est_cle=False):
    with open(chemin, "wb") as f:
        if est_cle:
            f.write(objet.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        else:
            f.write(objet.public_bytes(serialization.Encoding.PEM))


# 1) Autorite de certification (CA)
ca_cle = nouvelle_cle()
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(nom("CA TP IDS"))
    .issuer_name(nom("CA TP IDS"))
    .public_key(ca_cle.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(debut)
    .not_valid_after(fin)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=False, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=True,
        crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_cle.public_key()), critical=False)
    .sign(ca_cle, hashes.SHA256())
)

# 2) Certificat du serveur, signe par la CA
srv_cle = nouvelle_cle()
srv_cert = (
    x509.CertificateBuilder()
    .subject_name(nom("localhost"))
    .issuer_name(ca_cert.subject)
    .public_key(srv_cle.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(debut)
    .not_valid_after(fin)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, content_commitment=False, key_encipherment=True,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .add_extension(x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_cle.public_key()), critical=False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cle.public_key()), critical=False)
    .sign(ca_cle, hashes.SHA256())
)

ecrire_pem(ca_cert, "certs/ca.crt")
ecrire_pem(srv_cert, "certs/server.crt")
ecrire_pem(srv_cle, "certs/server.key", est_cle=True)
print("Certificats crees dans le dossier certs/ : ca.crt, server.crt, server.key")
