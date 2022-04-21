from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec




with open('./files/chave.key', 'rb') as file:
	encrypted_pem_private_key = file.read()


print('Arquivo carregado!')
#print(encrypted_pem_private_key)

private_key = serialization.load_pem_private_key(
		encrypted_pem_private_key,
		password = b'3011'
	)

print('Chave carregada com sucesso!')

signature = private_key.sign(
		b'teste',
		ec.ECDSA(hashes.SHA256())
	)

print('Assinatura feita com sucesso')

with open('./files/assinatura.asc', 'wb') as file:
	file.write(signature)
