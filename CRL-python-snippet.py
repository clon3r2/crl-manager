from cryptography import x509
from cryptography.hazmat.backends import default_backend


def cert_is_revoked(crl: x509.CertificateRevocationList, certificate: x509.Certificate) -> bool:
    return crl.get_revoked_certificate_by_serial_number(certificate.serial_number) is not None


def read_crl(name: str, type: str) -> x509.CertificateRevocationList:
    if type == "der":
        with open(name, 'rb') as f:
            return x509.load_der_x509_crl(f.read(), default_backend())

    if type == "pem":
        with open(name, 'rb') as f:
            return x509.load_pem_x509_crl(f.read(), default_backend())


def read_certificate(name: str, type: str) -> x509.Certificate:
    if type == "der":
        with open(name, 'rb') as f:
            return x509.load_der_x509_certificate(f.read(), default_backend())

    if type == "pem":
        with open(name, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())


crl = read_crl('crl_out.crl', 'der')
certificate = read_certificate('cert.pem', 'pem')


print(f'cert serial_Number: {certificate.serial_number}')
print(f'cert is revoked : {cert_is_revoked(crl=crl, certificate=certificate)}')
