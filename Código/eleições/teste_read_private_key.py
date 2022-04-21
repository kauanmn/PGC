# versão 0010
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sympadding # padding para cifra simétrica AES
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from secrets import token_bytes
from time import sleep

# dado o caminho, o usuário faz o input da senha e a função retorna a chave privada
def read_private_key(path):

	for i in range(1,4):
		try:
			passwd = input('Insira sua senha: ').encode()

			with open(path, 'rb') as file:
				private_key = serialization.load_pem_private_key(
					file.read(),
					password = passwd
				)

			print('Chave carregada com sucesso!')
			return private_key

		except:
			print('Senha incorreta. Você tem mais', 3 - i , 'tentativas.')

	print('Você errou a senha três vezes.')
	exit()


ct_private_key = read_private_key('./files/carteira/chave.pem')
