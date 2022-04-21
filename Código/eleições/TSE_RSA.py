from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

print('gerando chave RSA...')

private_key = rsa.generate_private_key(
	public_exponent=65537,
	key_size = 4096
)

print('chave RSA gerada')

public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print('chave pública extraída')

private_key_pem = private_key.private_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PrivateFormat.PKCS8,
	encryption_algorithm=serialization.BestAvailableEncryption(b'9999')
)

print('chave privada extraída')

with open('files/public_key.pem', 'wb') as file:
    file.write(public_key_pem)

print('chave publica salva')

with open('files/private_key.pem', 'wb') as file:
	file.write(private_key_pem)

print('chave privada salva')