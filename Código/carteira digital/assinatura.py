from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def load_private_key(path, passwd):
	with open(path, 'rb') as file:
		return serialization.load_pem_private_key(
				file.read(),
				password = passwd
			)

def sign(private_key, data):
	return private_key.sign(
			data,
			ec.ECDSA(hashes.SHA384()) 
		)

def save_file(data, path):
	with open(path, 'wb') as file:
		file.write(data)


private_key = load_private_key('./files/chave.key', b'3011')
print('Chave carregada com sucesso!')


signature = sign(private_key, b'teste')
print('Assinatura feita com sucesso')


save_file(signature, './files/assinatura.asc')