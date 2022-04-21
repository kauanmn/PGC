from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.backends import default_backend




with open('./files/certificado.pem', 'rb') as file:
	cert = file.read()

key = x509.load_pem_x509_certificate(cert, backend=default_backend())
public_key = key.public_key()

with open('./files/assinatura.asc', 'rb') as file:
	signature = file.read()

public_key.verify(signature, b'teste', ec.ECDSA(hashes.SHA256()))