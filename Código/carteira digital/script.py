# emitir cartão v0003

from header import * # importar o cabeçalho
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
    print('\n')


# definir o PIN para proteger a chave privada
def definir_pin():
    while(True):
        pin = input('Escreva um PIN de 4 dígitos para proteger sua chave privada:\n')
        if re.match(r"^\d{4}$", pin):
            return pin.encode()
        else:
            print('PIN inválido.')

# gerar chave com a curva elíptica NIST P-384
def gerar_chave():
    return ec.generate_private_key (
            ec.SECP384R1()
        )

# gerar certificado digital
def gerar_certificado(nome, cartorio_nome, private_key):

    atributo_nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nome)])
    atributo_cartorio = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cartorio_nome)])
    now = datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(atributo_nome)
        .issuer_name(atributo_cartorio)
        .public_key(private_key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after (now+timedelta(days=10*365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), False)
        .sign(private_key, hashes.SHA384(), default_backend())
    )

    return cert


# dado o filepath e os dados, salva o arquivo
def salvar_arquivo(path, data):
    with open(path, 'wb') as file:
        file.write(data)



######################################################

# imprimir o cabeçalho
cabecalho()


# PAR DE CHAVE / CERTIFICADO DE AUTENTICAÇÃO

# definir o PIN para o primeiro par de chave e certificado
pin = definir_pin()


# gerar chave privada
print('Gerando chave privada...')
private_key = gerar_chave()
public_key  = private_key.public_key()
sleep(2)
print('Chave gerada com sucesso!')


# gerar certificado digital x509
sleep(1)
print('Gerando certificado...')
cert = gerar_certificado("Kauan", "Cartorio Santo Andre", private_key)
sleep(2)
print('Certificado gerado com sucesso!')


sleep(1)
print('Salvando informações usando a codificação PEM...')
sleep(2)
cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
private_key_pem  = private_key.private_bytes(
    encoding = serialization.Encoding.PEM,
    format  = serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm = serialization.BestAvailableEncryption(pin)
)

# salvar o certificado
salvar_arquivo('files/certificado.pem', cert_pem)

# salvar a chave privada protegida pelo PIN
salvar_arquivo('files/chave.pem', private_key_pem)

print('Arquivos salvos com sucesso.')
