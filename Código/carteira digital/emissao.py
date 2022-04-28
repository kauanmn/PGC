# emitir cartão 20220422

from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from time import sleep
import re


### DEFINIÇÕES DE FUNÇÕES ###


# cabeçalho
def cabecalho():
    print('***********************************************')
    print('*                                             *')
    print('*  EMISSÃO DA CARTEIRA DE IDENTIDADE DIGITAL  *')
    print('*                                             *')
    print('***********************************************')


# definir o PIN para proteger a chave privada
def set_pin():
    while(True):
        pin = input('\nEscreva um PIN de 4 dígitos para proteger sua chave privada:\n')
        if re.match(r"^\d{4}$", pin):
            return pin.encode()
        else:
            print('\nPIN inválido.')

# definir o nome do proprietário da emissão da carteira
def set_owner_name():
    name = str(input("\nQual é o seu nome?\n"))
    return name

# definir o nome da autoridade certificadora
def set_issuer_name():
    name = str(input("\nIdentificação do emissor da carteira de identidade:\n"))
    return name

# gerar chave com a curva elíptica NIST P-384
def gen_key():
    return ec.generate_private_key (
            ec.SECP384R1()
        )

# gerar certificado digital
def gen_cert(owner_name, issuer_name, private_key):
    name_attribute_owner  = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, owner_name)])
    name_attribute_issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    now = datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(name_attribute_owner)
        .issuer_name(name_attribute_issuer)
        .public_key(private_key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after (now+timedelta(days=10*365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), False)
        .sign(private_key, hashes.SHA384(), default_backend())
    )

    return cert


# dado o caminho e os dados, salva o arquivo
def save_file(path, data):
    with open(path, 'wb') as file:
        file.write(data)



######################################################

# imprimir o cabeçalho
cabecalho()


# definir os nomes das partes envolvidas na emissão
owner_name  = set_owner_name()
issuer_name = set_issuer_name()


# PAR DE CHAVE / CERTIFICADO DE AUTENTICAÇÃO

# definir o PIN para o primeiro par de chave e certificado
pin = set_pin()


# gerar chave privada
sleep(1)
print('\nGerando chave privada...')
sleep(2)
private_key = gen_key()
public_key  = private_key.public_key()
print('Chave gerada com sucesso!')


# gerar certificado digital x509
sleep(1)
print('Gerando certificado...')
cert = gen_cert(owner_name, issuer_name, private_key)
sleep(2)
print('Certificado gerado com sucesso!')


# codificar a chave e o certificado usando PEM
sleep(1)
print('Salvando informações usando a codificação PEM...')
sleep(2)
cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
private_key_pem  = private_key.private_bytes(
    encoding = serialization.Encoding.PEM,
    format  = serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm = serialization.BestAvailableEncryption(pin)
)

save_file('files/certificado.pem', cert_pem)                    # salvar o certificado
save_file('files/chave.pem', private_key_pem)                   # salvar a chave privada protegida pelo PIN
save_file('files/nome', bytes(owner_name, encoding=('utf-8')))  # salvar o nome do proprietário

print('Arquivos salvos com sucesso.\n')