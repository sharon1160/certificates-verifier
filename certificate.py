from oscrypto import tls
from certvalidator import CertificateValidator, errors
from certvalidator.path import ValidationPath
from asn1crypto.x509 import Certificate, Name
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
