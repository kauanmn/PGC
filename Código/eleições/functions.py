# versão 20220510


from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sympadding # padding para cifra simétrica AES
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from secrets import token_bytes


############################################

'''
CERTIFICATE FUNCTIONS
'''

# dado o caminho, a função retorna o certificado x509
def read_certificate(path):
	with open(path, 'rb') as file:
		cert_pem = file.read()
	return x509.load_pem_x509_certificate(cert_pem)


# extrair o nome do proprietário do certificado
def get_cert_subject(cert):
	return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


# extrair o nome do emissor do certificado
def get_cert_issuer(cert):
	return cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value




############################################

'''
PUBLIC KEY FUNCTIONS
'''


# ler chave pública de um arquivo .pem
def read_public_key(path):
	with open(path, 'rb') as file:
		return serialization.load_pem_public_key(file.read())


# dado um certificado x509, extrair a chave pública
def read_public_key_x509(cert):
	return cert.public_key()



############################################

'''
PRIVATE KEY FUNCTIONS
'''


# dado o arquivo e a senha, a função retorna a chave privada
def get_private_key(path, passwd):
	with open(path, 'rb') as file:
		private_key = serialization.load_pem_private_key(
			file.read(),
			password = passwd
		)
	return private_key


def load_private_key(path):
	for i in range(1,4):
		try:
			passwd = input('Insira seu PIN de 4 dígitos: ').encode()
			private_key = get_private_key(path, passwd)
			print('Chave carregada com sucesso.\n')
			return private_key
		except:
			print('PIN incorreto. Você tem mais', 3 - i , 'tentativas.\n')
	print('Você errou o PIN três vezes. Saindo da aplicação...')
	exit()




############################################

'''
AES CIPHER FUNCTIONS
'''


def aes_encrypt(data, key, iv):
	aes = Cipher(algorithms.AES(key), modes.CBC(iv))
	encryptor = aes.encryptor()

	padder = sympadding.PKCS7(128).padder()
	padded_data = padder.update(data) + padder.finalize()
	return encryptor.update(padded_data) + encryptor.finalize()


def aes_decrypt(data, key, iv):
	aes  = Cipher(algorithms.AES(key), modes.CBC(iv))
	decryptor = aes.decryptor()

	decrypted_data = decryptor.update(data) + decryptor.finalize()
	unpadder = sympadding.PKCS7(128).unpadder()
	return unpadder.update(decrypted_data) + unpadder.finalize()



############################################

'''
FILES FUNCTIONS
'''

# carregar os arquivos que foram "enviados"
def load_file(path):
	with open(path, 'rb') as file:
		return file.read()

# salvar arquivo
def save_file(data, path):
	with open(path, 'wb') as file:
		file.write(data)


############################################

'''
ECDH
'''

def derive_key(your_private_key, their_public_key):
	shared_key = your_private_key.exchange(ec.ECDH(), their_public_key)
	return HKDF(
		algorithm=hashes.SHA384(),
		length=32,
		salt=None,
		info=None
	).derive(shared_key)


############################################

'''
SIGNATURE FUNCTIONS
'''


# verify signature
def verify_signature(ec_public_key, signature, data):
	is_valid = False
	try:
		ec_public_key.verify(signature, data, ec.ECDSA(hashes.SHA384()))
		is_valid = True
	except:
		pass
	return is_valid



# sign with SHA384
def sign(ec_private_key, data):
	return ec_private_key.sign(
			data,
			ec.ECDSA(hashes.SHA384())
		)


############################################

'''
VOTE FUNCTIONS
'''

# função para escolher o voto
def set_vote():
	vote = int(input('Escolha o seu voto: '))
	print('Seu voto é {}'.format(vote))
	return vote.to_bytes(length = 3, byteorder='big')


def decode_vote(vote_encoded):
	return int.from_bytes(vote_encoded, byteorder='big')


############################################

'''
RSA FUNCTIONS
'''

def rsa_encrypt(key, data):
	return key.encrypt(
		data,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA384()),
			algorithm=hashes.SHA384(),
			label=None
		)
	)

def rsa_decrypt(key, data):
	return key.decrypt(
		data,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA384()),
			algorithm=hashes.SHA384(),
			label=None
		)
	)