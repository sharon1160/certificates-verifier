from operator import ge
import requests
from oscrypto import tls
from certvalidator import CertificateValidator, errors
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from OpenSSL import SSL, crypto
import socket
import ssl
import re


def is_valid_URL(url):
  '''
  Función que valida la sintaxis y existencia de una URL en Internet
  '''
  is_valid = True
  response = ""
  try:
    response = requests.get(url, timeout = 3) # 3 segundos
    print("URL is valid and exists on the internet")
  # Si la URL supera el tiempo de espera (3 segundos)
  except requests.exceptions.Timeout:
    response = "Timeout error"
    print(response)
    is_valid = False
  # Si la URL no existe en Internet
  except requests.ConnectionError:
    response = "URL does not exist on Internet or invalid syntax"
    print(response)
    is_valid = False
  # Si la URL no tiene la implementación del protocolo HTTPS
  except requests.exceptions.RequestException:
    response = "Invalid syntax"
    print(response)
    is_valid = False
  return is_valid, response

def get_file_valid_urls(file_urls):
  '''
  Función que valida URLs del archivo y almacena solo aquellas que son válidas
  '''
  list_file_urls = []
  list_file_colors = []
  counter = 1
  for url in file_urls:
    # validación de URL
    valid_url, response = is_valid_URL(url)

    # si es válida y existe la URL
    if valid_url == True:
      list_file_urls.insert(0, url)

      # Funcion que verifica el nivel de confianza
      lista_browsers_colors = get_results(url)
      list_file_colors.insert(0, lista_browsers_colors)
    else:
      # Para mostrar mensajes de error
      print("URL #", counter, " inválida")
    counter += 1
  return list_file_urls, list_file_colors

def get_name(certificado):
    for i in certificado.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
        return i.value

def get_issuer(certificado):
    for i in certificado.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
      return i.value

def get_public_key_algorithm_format(certificado):
    format =  certificado.signature_hash_algorithm.name + ' - ' +str(certificado.public_key().key_size) + ' bits'
    return format

def format_date(date):
    date = date.split(' ')
    month = date[1]
    day = date[2]
    year = date[0]
    month = month_number(month)
    date = year + '-' + month + '-' + day
    return date

def month_number(month):
    months = {
        'Jan': '01',
        'Feb': '02',
        'Mar': '03',
        'Apr': '04',
        'May': '05',
        'Jun': '06',
        'Jul': '07',
        'Aug': '08',
        'Sep': '09',
        'Oct': '10',
        'Nov': '11',
        'Dec': '12'
    }
    return months[month]

def get_key_usage(cert):
    usage =""
    try:
        cert.extensions.get_extension_for_class(x509.KeyUsage)
    except:
        usage = 'UNDENTIFIED'
        return usage

    if cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature == True:
        usage = usage + 'Digital Signature, '
    if cert.extensions.get_extension_for_class(x509.KeyUsage).value.content_commitment == True:
        usage = usage + 'Content Commitment, '
    if cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment == True:
        usage = usage + 'Key Encipherment, '
    if cert.extensions.get_extension_for_class(x509.KeyUsage).value.data_encipherment == True:
        usage = usage + 'Data Encipherment, '
    if cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_agreement == True:
        usage = usage + 'Key Agreement, '
    if cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign == True:
        usage = usage + 'Key Cert Sign, '
    if cert.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign == True:
        usage = usage + 'Crl Sign, '
    return usage

def read_certificate_pem(cert):
    """
    Funcion que lee un certificado en formato PEM y retorna un diccionario con los datos del certificado   
    """
    cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
    key_usage = get_key_usage(cert)
    name = get_name(cert)
    Public_Key_Algorithm_format = get_public_key_algorithm_format(cert)
    cert_dict = {
        "Common name": name,
        "issuer": get_issuer(cert),
        "valid_before": cert.not_valid_before.strftime("%Y-%m-%d"),
        "valid_after": cert.not_valid_after.strftime("%Y-%m-%d"),
        "Public Key Algorithm": Public_Key_Algorithm_format,
        "key usage": key_usage,
        "SHA-1": (':'.join(cert.fingerprint(hashes.SHA1()).hex().upper()[i:i+2] for i in range(0, len(cert.fingerprint(hashes.SHA1()).hex().upper()), 2)))
    }
    return cert_dict

def read_pem_certificates(file):
    """
    Funcion que lee un archivo con varios certificados en formato PEM y retorna un arreglo de diccionarios con los datos de los certificados
    """
    certs_array = []
    with open(file, 'r') as f:
        certs = f.read()
        certs = certs.split('-----END CERTIFICATE-----')
        certs.pop()
        for cert in certs:
            cert = cert + '-----END CERTIFICATE-----'
            cert_dict = read_certificate_pem(cert)
            certs_array.append(cert_dict)
    return certs_array

def read_csv_certificates(file):
    """
    Funcion que lee un archivo con varios certificados en formato CSV y retorna un arreglo de diccionarios con los datos de los certificados
    """
    certs_array = []
    with open(file, encoding='utf8') as f:
        for line in f:
            line = line.split('","')
            valid_before = format_date(line[4])
            valid_after = format_date(line[5])
            cert_dict = {
                "Common name": line[1],
                "valid_before": valid_before,
                "valid_after": valid_after,
                "Public Key Algorithm": line[6],
                "key usage": line[8].replace(';', ','),
                "SHA-1": (':'.join(line[2].upper()[i:i+2] for i in range(0, len(line[2].upper()), 2)))
            }
            certs_array.append(cert_dict)
    return certs_array

def structure_trust_store(certificates):
  '''
  Función que reestructura una lista de certificados de un trust store
  '''
  certificates_list = []
  for certificate in certificates:
    certificate_dic = {'Common name':certificate['Common name'],
                      'validity': certificate['valid_before'] + " - " + certificate['valid_after'],
                      'Public Key Algorithm': certificate['Public Key Algorithm'],
                      'key-usage': certificate['key usage'],
                      'SHA-1': certificate['SHA-1']}
    certificates_list.append(certificate_dic)
  return certificates_list

def get_trust_stores():
  '''
  Función retorna los trusts stores de los 3 navegadores
  '''
  microsoft_edge = read_csv_certificates("verifierApp/static/data/Microsoft_Edge.csv")
  google_chrome = read_pem_certificates("verifierApp/static/data/Google_Chrome.pem")
  mozilla_firefox = read_pem_certificates("verifierApp/static/data/Mozilla_Firefox.pem")

  microsoft_edge = structure_trust_store(microsoft_edge)
  google_chrome = structure_trust_store(google_chrome)
  mozilla_firefox = structure_trust_store(mozilla_firefox)

  return microsoft_edge, google_chrome, mozilla_firefox



