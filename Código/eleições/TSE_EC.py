from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization



private_key = ec.generate_private_key (
	ec.SECP384R1()
)

private_key_pem = private_key.private_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PrivateFormat.PKCS8,
	encryption_algorithm=serialization.BestAvailableEncryption(b'9999')
)

public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PublicFormat.SubjectPublicKeyInfo
)


with open('./files/tse/ec_public_key.pem', 'wb') as file:
    file.write(public_key_pem)

print('chave publica salva')

with open('./files/tse/ec_private_key.pem', 'wb') as file:
	file.write(private_key_pem)

print('chave privada salva')