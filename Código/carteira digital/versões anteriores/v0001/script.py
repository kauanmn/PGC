# emitir cartão v0.01.06

from header import * # importar o cabeçalho
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import ipaddress
import re


### DEFINIÇÕES DE FUNÇÕES ###

# definir o PIN para proteger a chave privada
def definir_pin():
    while(True):
        pin = input('Escreva um PIN de 4 dígitos para proteger sua chave privada:\n')
        if re.match(r"^\d{4}$", pin):
            return pin.encode()
        else:
            print('PIN inválido.')
    return pin


# gerar chave com a curva elíptica NIST P-384
def gerar_chave():
    return ec.generate_private_key (
            ec.SECP384R1()
        )

# salvar chave em um arquivo .key (protegido por PIN)
def salvar_chave(key_pem):
    with open('files/chave.key', 'wb') as file:
        file.write(key_pem)

# salvar certificado em arquivo .pfx
def salvar_cert(cert_pem):
    with open('files/certificado.pem', 'wb') as file:
        file.write(cert_pem)



######################################################


# definir o PIN para o primeiro par de chave e certificado
pin1 = definir_pin()

print('Gerando chave privada...')


# gerar chave privada
key = gerar_chave()
print('Chave gerada com sucesso!')



nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kauan")])
cartorio_nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cartório de Santo André")])
now = datetime.utcnow()


cert = (
    x509.CertificateBuilder()
    .subject_name(nome)
    .issuer_name(cartorio_nome)
    .public_key(key.public_key())
    .serial_number(1000)
    .not_valid_before(now)
    .not_valid_after (now+timedelta(days=10*365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), False)
    .sign(key, hashes.SHA256(), default_backend())
)

cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)


key_pem  = key.private_bytes(
    encoding = serialization.Encoding.PEM,
    format  = serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm = serialization.BestAvailableEncryption(pin1)
)

# salvar as informações no arquivo .pfx (certificado digital)
salvar_cert(cert_pem)

# salvar a chave privada protegida no arquivo .key
salvar_chave(key_pem)