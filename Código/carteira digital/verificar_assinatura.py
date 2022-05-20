from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.backends import default_backend



# função para ler o certificado
def load_cert(path):
	with open(path, 'rb') as file:
		cert = file.read()
	return x509.load_pem_x509_certificate(cert, backend=default_backend())


# função para ler assinatura (idêntica à primeira função)
def load_signature(path):
	with open(path, 'rb') as file:
		return file.read()


# função para verificar a validade da assinatura
def verify_signature(public_key, signature, data):
	is_valid = False
	try:
		public_key.verify(signature, data, ec.ECDSA(hashes.SHA384()))
		is_valid = True
	except:
		pass
	return is_valid



cert = load_cert('./files/certificado.pem')    # carregar o certificado
public_key = cert.public_key()						 # carregar a chave pública através do certificado
signature = load_signature('./files/assinatura.asc') # abrir assinatura digital
data = b'teste'                                      # dados que foram assinados



# verificar assinatura
if(verify_signature(public_key, signature, data)):
	print('A assinatura é válida.')
else:
	print('A assinatura é inválida.')