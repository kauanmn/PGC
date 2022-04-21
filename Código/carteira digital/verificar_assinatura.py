from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.backends import default_backend



# função para ler o certificado
def ler_certificado(path):
	with open(path, 'rb') as file:
		cert = file.read()

def ler_chave_publica(cert):
	key = x509.load_pem_x509_certificate(cert, backend=default_backend())
	return key.public_key()

# função para ler assinatura (idêntica à primeira função)
def ler_assinatura(path):
	with open(path, 'rb') as file:
		return file.read()

# função para verificar a validade da assinatura
def verificar_assinatura(public_key, signature, data):
	is_valid = False
	try:
		public_key.verify(signature, data, ec.ECDSA(hashes.SHA384()))
		is_valid = True
	except:
		pass

	return is_valid




# abrir o certificado
cert = ler_certificado('./files/certificado.pem')

# carregar chave pública através do certificado
public_key = ler_chave_publica(cert)

# abrir assinatura digital
signature = ler_assinatura('./files/assinatura.asc')

# dados que foram assinados
data = b'teste'

# verificar assinatura
is_valid = False

try:
	public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
	is_valid = True
except:
    pass