# versão 0010
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sympadding # padding para cifra simétrica AES
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from secrets import token_bytes
from time import sleep


def welcome(name):
	print("*******************")
	print("*                 *")
	print("*  ELEIÇÕES 2042  *")
	print("*                 *")
	print("*******************\n\n")
	print("Seja bem-vindo(a) às eleições digitais de 2042, Sr(a). {}\n".format(name))



def get_private_key(path, passwd):
	with open(path, 'rb') as file:
		private_key = serialization.load_pem_private_key(
			file.read(),
			password = passwd
		)
	return private_key


# dado o caminho, o usuário faz o input da senha e a função retorna a chave privada
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

# dado o caminho, a função retorna o certificado x509
def read_certificate(path):
	with open(path, 'rb') as file:
		cert_pem = file.read()
	cert = x509.load_pem_x509_certificate(cert_pem)
	return cert

# ler chave pública de um arquivo .pem
def read_public_key(path):
	with open(path, 'rb') as file:
		return serialization.load_pem_public_key(file.read())

# salvar arquivo
def save_file(data, filename):
	with open('./files/envio/'+filename, 'wb') as file:
		file.write(data)

def aes_encrypt_data(data, key, iv):
	aes = Cipher(algorithms.AES(key), modes.CBC(iv))
	encryptor = aes.encryptor()

	padder = sympadding.PKCS7(128).padder()
	padded_data = padder.update(data) + padder.finalize()
	return encryptor.update(padded_data) + encryptor.finalize()

# ECDH (troca de chaves)
def derive_key(your_private_key, their_public_key):
	shared_key = your_private_key.exchange(ec.ECDH(), their_public_key)
	return HKDF(
		algorithm=hashes.SHA384(),
		length=32,
		salt=None,
		info=None
	).derive(shared_key)

# função para escolher o voto
def set_vote():
	vote = int(input('Escolha o seu voto: '))
	print('Seu voto é {}'.format(vote))
	return vote.to_bytes(length = 3, byteorder = 'big')

# extrair o nome do proprietário do certificado
def get_cert_subject(cert):
	return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

# extrair o nome do emissor do certificado
def get_cert_issuer(cert):
	return cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value





#########################################


# CERTIFICADO
# carregar certificado digital
print('Carregando seu certificado digital...')
sleep(2)
cert = read_certificate('./files/carteira/certificado.pem')
print('Certificado carregado.\n\n')

eleitor_nome = get_cert_subject(cert) # obter o nome do eleitor pelo certificado
welcome(eleitor_nome)



# CHAVE PRIVADA DO CLIENTE
# usada para autenticação / assinatura digital
print('\nPara prosseguir com a votação, precisamos validar a sua identidade.')
ct_private_key = load_private_key('./files/carteira/chave.pem') # carregar a chave privada
ct_public_key  = ct_private_key.public_key()
print('Pronto. Agora iremos carregar as informações necessárias...\n')



# CHAVES PÚBLICAS DO TSE

# carregar chaves públicas do TSE (RSA e EC) direto do arquivo
print('Carregando as chaves públicas do TSE...')
sleep(2)
tse_rsa_public_key = read_public_key('./files/tse/rsa_public_key.pem')
tse_ec_public_key  = read_public_key('./files/tse/ec_public_key.pem')
print('Chaves públicas carregadas.\n')
sleep(1)


# VOTO
voto = set_vote()
sleep(1)
print('\nCriptografando seu voto...')
sleep(1)

# criptografar o voto usando RSA
voto_secreto = tse_rsa_public_key.encrypt(
	voto,
	padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA384()),
		algorithm=hashes.SHA384(),
		label=None
	)
)
sleep(2)
print('O voto foi criptografado com sucesso.\n')



# ASSINATURA


# assinar o voto secreto usando ECDSA
print('Assinando seu voto...')
sleep(1)

assinatura = ct_private_key.sign(
	voto_secreto,
	ec.ECDSA(hashes.SHA384())
)

print('Assinatura digital feita com sucesso.\n')
sleep(1)



# estão prontos os dados: certificado, assinatura e voto secreto (criptografado)
# agora enviamos esses dados criptografados com ECDH


print('Criando conexão segura com o TSE...')
sleep(2)

derived_key = derive_key(ct_private_key, tse_ec_public_key)


# criptografar os dados para serem enviados com cifra simétrica AES CBC
print('Criptografando os dados...')
sleep(2)
iv = token_bytes(16)
# initialization vector (IV), não é uma informação pública
# o IV deve ser único para cada par (mensagem, chave)


cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM) # certificado
ct_public_key_pem = ct_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)


# criptografar os arquivos usando AES e a chave derivada do ECDH
enc_voto_secreto = aes_encrypt_data(voto_secreto, derived_key, iv)
enc_assinatura   = aes_encrypt_data(assinatura,   derived_key, iv)
enc_cert         = aes_encrypt_data(cert_pem,     derived_key, iv)


# simulação do envio
print('Enviando os dados...')
sleep(2)
save_file(enc_voto_secreto, 'enc_voto_secreto')
save_file(enc_assinatura,   'enc_assinatura')
save_file(enc_cert,         'enc_cert')
save_file(ct_public_key_pem,'chave_publica_eleitor.pem')
save_file(iv, 'iv') # o IV é uma informação pública usada na cifra AES-CBC

print('\nPronto. Seu voto foi enviado ao TSE. Agora é só esperar os resultados.')