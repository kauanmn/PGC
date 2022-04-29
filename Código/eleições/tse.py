from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sympadding # padding para cifra simétrica AES
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from secrets import token_bytes
from time import sleep

# dado o caminho, a função retorna o certificado
def read_certificate(path):
	with open(path, 'rb') as file:
		cert = file.read()
	return cert

# dado o arquivo e a senha, a função retorna a chave privada
def read_private_key(path, passwd):
	with open(path, 'rb') as file:
		private_key = serialization.load_pem_private_key(
			file.read(),
			password = passwd
		)
	return private_key

# ler chave pública de um arquivo .pem
def read_public_key(path):
	with open(path, 'rb') as file:
		return serialization.load_pem_public_key(file.read())

# carregar os arquivos que foram "enviados"
def load_file(path):
	with open(path, 'rb') as file:
		return file.read()

def aes_decrypt_data(data, derived_key, iv):
	aes  = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
	decryptor = aes.decryptor()

	decrypted_data = decryptor.update(data) + decryptor.finalize()
	unpadder = sympadding.PKCS7(128).unpadder()
	return unpadder.update(decrypted_data) + unpadder.finalize()

# ECDH (troca de chaves)
def derive_key(your_private_key, their_public_key):
	shared_key = your_private_key.exchange(ec.ECDH(), their_public_key)
	return HKDF(
		algorithm=hashes.SHA384(),
		length=32,
		salt=None,
		info=None
	).derive(shared_key)

def read_public_key_x509(cert_pem):
	cert = x509.load_pem_x509_certificate(cert_pem)
	return cert.public_key()

def verificar_assinatura(public_key, signature, data):
	is_valid = False
	try:
		public_key.verify(signature, data, ec.ECDSA(hashes.SHA384()))
		is_valid = True
	except:
		pass
	return is_valid

def decrypt_vote(secret_vote, private_key):
	vote_bytes = private_key.decrypt(
		secret_vote,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA384()),
			algorithm=hashes.SHA384(),
			label=None
		)
	)
	vote = int.from_bytes(vote_bytes, byteorder='big')
	return vote

# extrair o nome do proprietário do certificado
def get_cert_subject(cert):
	return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

# extrair o nome do emissor do certificado
def get_cert_issuer(cert):
	return cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

# caminho das informações enviadas
path_envio = './files/envio/'
path_tse   = './files/tse/'

# carregar os arquivos
enc_voto_secreto = load_file(path_envio + 'enc_voto_secreto')
enc_assinatura   = load_file(path_envio + 'enc_assinatura')
enc_cert_pem     = load_file(path_envio + 'enc_cert')
iv               = load_file(path_envio + 'iv')


ct_public_key = read_public_key(path_envio + 'chave_publica_eleitor.pem')

# carregar chaves privadas TSE
tse_ec_private_key  = read_private_key(path_tse +  'ec_private_key.pem', b'9999')
tse_rsa_private_key = read_private_key(path_tse + 'rsa_private_key.pem', b'9999')

# derivar a chave usada no AES usando ECDH
derived_key = derive_key(tse_ec_private_key, ct_public_key)

# descriptografar as informações recebidas pelo eleitor
voto_secreto = aes_decrypt_data(enc_voto_secreto, derived_key, iv)
assinatura   = aes_decrypt_data(enc_assinatura  , derived_key, iv)
cert_pem     = aes_decrypt_data(enc_cert_pem    , derived_key, iv)

cert = x509.load_pem_x509_certificate(cert_pem)

# verificar assinatura
validade_assinatura = verificar_assinatura(
	public_key = ct_public_key,
	signature  = assinatura,
	data = voto_secreto
)

if(validade_assinatura):
	voto = decrypt_vote(voto_secreto, tse_rsa_private_key)
	print('Bem-vindo ' + get_cert_subject(cert))
	print('Sua carteira de identidade foi emitida por {}'.format(get_cert_issuer(cert)))
	print('Seu voto é válido e foi contabilizado!')
	print('Você votou em {}'.format(voto))
else:
	print('Certificado inválido. Voto descartado.')