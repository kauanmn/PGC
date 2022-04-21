from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def carregar_chave_privada(path, passwd):
	with open(path, 'rb') as file:
		private_key = serialization.load_pem_private_key(
				file.read(),
				password = passwd
			)
	return private_key

def assinar(private_key, data):
	return private_key.sign(
			data,
			ec.ECDSA(hashes.SHA384())
		)

def salvar_assinatura(path, signature):
	with open(path, 'wb') as file:
		file.write(signature)


with open('./files/chave.key', 'rb') as file:
	private_key = serialization.load_pem_private_key(
		file.read(),
		password = b'3011'
	)

print('Chave carregada!')


print('Chave carregada com sucesso!')

signature = private_key.sign(
		b'teste',
		ec.ECDSA(hashes.SHA256())
	)

print('Assinatura feita com sucesso')

with open('./files/assinatura.asc', 'wb') as file:
	file.write(signature)
