# versão 20220510

from functions import *
from time import sleep

# caminho das informações enviadas
path_envio = './files/envio_temp/'
path_tse   = './files/tse/'

# carregar os arquivos
enc_voto       = load_file(path_envio + 'enc_voto')
enc_assinatura = load_file(path_envio + 'enc_assinatura')
enc_cert_pem   = load_file(path_envio + 'enc_cert')
iv             = load_file(path_envio + 'iv')


ct_public_key = read_public_key(path_envio + 'chave_publica_eleitor.pem')

# carregar chaves privadas TSE
tse_ec_private_key  = get_private_key(path_tse +  'ec_private_key.pem', b'9999')
tse_rsa_private_key = get_private_key(path_tse + 'rsa_private_key.pem', b'9999')

# derivar a chave usada no AES usando ECDH
derived_key = derive_key(tse_ec_private_key, ct_public_key)

# descriptografar as informações recebidas pelo eleitor
voto       = aes_decrypt(enc_voto       , derived_key, iv)
assinatura = aes_decrypt(enc_assinatura , derived_key, iv)
cert_pem   = aes_decrypt(enc_cert_pem   , derived_key, iv)

cert = x509.load_pem_x509_certificate(cert_pem)

# verificar assinatura
validade_assinatura = verify_signature(
	ec_public_key = ct_public_key,
	signature  = assinatura,
	data = voto
)

if(validade_assinatura):
	voto_int = decode_vote(voto)
	print('Bem-vindo ' + get_cert_subject(cert))
	print('Sua carteira de identidade foi emitida por {}'.format(get_cert_issuer(cert)))
	print('Seu voto é válido e foi contabilizado!')
	print('Você votou em {}'.format(voto_int))
else:
	print('Certificado inválido. Voto descartado.')