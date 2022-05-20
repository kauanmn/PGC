# versão 20220510

from functions import *
from time import sleep



# CERTIFICADO
# carregar certificado digital
print('Carregando seu certificado digital...')
sleep(2)
cert = read_certificate('./files/carteira/certificado.pem')
print('Certificado carregado.\n\n')

eleitor_nome = get_cert_subject(cert) # obter o nome do eleitor pelo certificado


print("*******************")
print("*                 *")
print("*  ELEIÇÕES 2042  *")
print("*                 *")
print("*******************\n\n")
print("Seja bem-vindo(a) às eleições digitais de 2042, Sr(a). {}\n".format(eleitor_nome))



# CHAVE PRIVADA DO CLIENTE
# usada para autenticação / assinatura digital
print('\nPara prosseguir com a votação, precisamos validar a sua identidade.')
ct_private_key = load_private_key('./files/carteira/chave.pem') # carregar a chave privada
ct_public_key  = read_public_key_x509(ct_private_key)
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
sleep(2)


# ASSINATURA


# assinar o voto secreto usando ECDSA
print('Assinando seu voto...')
sleep(1)

assinatura = sign(ct_private_key, voto)

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
enc_voto       = aes_encrypt(voto,         derived_key, iv)
enc_assinatura = aes_encrypt(assinatura,   derived_key, iv)
enc_cert       = aes_encrypt(cert_pem,     derived_key, iv)


envio_path = './files/envio_temp/'

# simulação do envio
print('Enviando os dados...')
sleep(2)
save_file(enc_voto,          envio_path + 'enc_voto')
save_file(enc_assinatura,    envio_path + 'enc_assinatura')
save_file(enc_cert,          envio_path + 'enc_cert')
save_file(ct_public_key_pem, envio_path + 'chave_publica_eleitor.pem')
save_file(iv,                envio_path + 'iv') # o IV é uma informação pública usada na cifra AES-CBC

print('\nPronto. Seu voto foi enviado ao TSE. Agora é só esperar os resultados.')