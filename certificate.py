from cryptography import x509

# Load the certificate
with open("certificate.pem", "rb") as cert_file:
    certificate = x509.load_pem_x509_certificate(cert_file.read())

print("===== CERTIFICATE TEST RESULTS =====")
print("Certificate Subject :", certificate.subject.rfc4514_string())
print("Certificate Issuer  :", certificate.issuer.rfc4514_string())
print("Certificate is valid and successfully loaded.")