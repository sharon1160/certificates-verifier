from oscrypto import tls
from certvalidator import CertificateValidator, errors
from verify import get_trust_stores
import re


def process_url(url):
    """
    Funcion que procesa una url y retorna el dominio 
    """
    return re.sub(r"^(https?|ftp|file)://", "", re.sub(r"^(.*\.(?:com|net|org|co|in)).*$", r"\1", url))


def get_certificate_chain(url):
    """
    Funcion que obtiene la cadena de certificados de un sitio web a partir de su URL
    """
    domain = process_url(url)
    session = tls.TLSSession(manual_validation=True) 
    try:
        connection = tls.TLSSocket(domain, 443, session=session)
    except Exception as e: 
        return None 
    try:
        validator = CertificateValidator(connection.certificate, connection.intermediates) 
        chain_certificate = validator.validate_tls(connection.hostname) 

    except (errors.PathValidationError): 
        print("The certificate did not match the hostname, or could not be otherwise validated")
        return
    connection.close()  
    return chain_certificate


def generate_dict_chain(chain):
    """
    Funcion que genera un arreglo de diccionario con los certificados de la cadena de certificados
    """
    dict_chain =[]
    for cert in chain:
        dict_cert = {
            "Subject" : cert.subject.native,
            "Isuuer" : cert.issuer.native,
            "Serial Number" : hex(cert.serial_number).upper(),
            "Not Valid Before" : cert.not_valid_before,
            "Not Valid After" : cert.not_valid_after,
            "Public Key Algorithm" : cert.public_key.algorithm.upper(),
            "SHA-1": cert.sha1_fingerprint,
            "CA" : cert.ca,
            "Max Path Length" : cert.max_path_length
            }
        dict_chain.append(dict_cert)
    return dict_chain


microsft_edge, google_chrome, mozilla_firefox = get_trust_stores()


def validate_chain(chain, trust_store):
    """
    Funcion que valida que el sha1 raiz de la cadena de certificados este en el trust store (trust_store es un arreglo de diccionarios)
    Funcion que valida si la fecha de expiracion del certificado raiz es mayor a la fecha actual: 
    por ejemplo si el certificado raiz expira el 2021-01-01 y la fecha actual es 2019-12-31 entonces el certificado no es valido
    """
    is_sha1_in_trust_store = False
    is_valid_date = False
    for cert in trust_store:
        sha1 = ":".join(chain[0]["SHA-1"][i:i+2] for i in range(0, len(chain[0]["SHA-1"]), 3))
        if sha1 == cert["SHA-1"]:
            is_sha1_in_trust_store = True
            # chain[0]["Not Valid After"] es la fecha de expiracion del certificado raiz en formato datetime

        print(chain[0]["Not Valid After"])
        print(cert["validity"])
        





url = "https://www.youtube.com"
chain = get_certificate_chain(url)
dict_chain = generate_dict_chain(chain)

if validate_chain(dict_chain, microsft_edge):
    print("The certificate chain is valid")
else:
    print("The certificate chain is not valid")




