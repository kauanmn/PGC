# versão 0008


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sympadding # padding para cifra simétrica AES (CBC Mode)
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from secrets import token_bytes

# dado o caminho e a senha, a função retorna a chave privada
def read_private_key(path, passwd):
	with open(path, 'rb') as file:
		ct_private_key = serialization.load_pem_private_key(
			file.read(),
			password = passwd
		)
	return ct_private_key

# dado o caminho, a função retorna o certificado
def read_certificate(path):
	with open(path, 'rb') as file:
		cert = file.read()
	return cert

# dado um certificado no formato PEM, a função extrai a chave pública
def read_public_key_x509(cert_pem):
	cert = x509.load_pem_x509_certificate(cert_pem)
	return cert.public_key()

# ler chave pública de um arquivo .pem
def read_public_key(path):
	with open(path, 'rb') as file:
		return serialization.load_pem_public_key(file.read())

# salvar arquivo
def save_file(data, filename):
		with open('./files/envio/'+filename, 'wb') as file:
			file.write(data)

# cifra simétrica usando chave derivada do ECDH
def aes_encrypt_data(data, derived_key, iv):
	aes = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
	encryptor = aes.encryptor()

	padder = sympadding.PKCS7(128).padder()
	padded_data = padder.update(data) + padder.finalize()
	return encryptor.update(padded_data) + encryptor.finalize()

# cifra simétrica usando chave derivada do ECDH
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


# escolher um inteiro
voto_int = 99
voto = voto_int.to_bytes(length = 3, byteorder = 'big')


# carregar chaves públicas do TSE (RSA e EC) direto do arquivo
tse_rsa_public_key = read_public_key('./files/tse/rsa_public_key.pem')
tse_ec_public_key  = read_public_key('./files/tse/ec_public_key.pem')


# carregar certificado digital
cert = read_certificate('./files/carteira/certificado.pem')

# criptografar o voto usando RSA
voto_secreto = tse_rsa_public_key.encrypt(
	voto,
	padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA384()),
		algorithm=hashes.SHA384(),
		label=None
	)
)



# pwd = input('Insira a senha: ')
ct_private_key = read_private_key('./files/carteira/chave.pem', b'3011')

# assinar o voto secreto usando ECDSA
assinatura = ct_private_key.sign(
	voto_secreto,
	ec.ECDSA(hashes.SHA384())
)


# cert, assinatura, voto_secreto
# enviar esses dados criptografados com ECDH
derived_key = derive_key(ct_private_key, tse_ec_public_key)


# ECDH
# DADOS, CHAVE DERIVADA, IV

iv = token_bytes(16) # initialization vector (IV), não é uma informação pública
# o IV deve ser único para cada par (mensagem, chave)

# criptografar os dados para serem enviados
enc_voto_secreto = aes_encrypt_data(voto_secreto, derived_key, iv)
enc_assinatura   = aes_encrypt_data(assinatura,   derived_key, iv)
enc_cert         = aes_encrypt_data(cert,         derived_key, iv)


# simulação do envio
save_file(enc_voto_secreto, 'enc_voto_secreto')
save_file(enc_assinatura, 'enc_assinatura')
save_file(enc_cert, 'enc_cert')
save_file(iv, 'iv') # o IV é uma informação pública usada na cifra AES-CBC