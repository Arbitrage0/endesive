import sys
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from endesive.pdf import cms

#create test external key/sig (assume this will be an online HSM so no access to private key directly)

private_key = rsa.generate_private_key(
  public_exponent=65537,
  key_size=2048,
  backend=default_backend()
)
public_key = private_key.public_key()
builder = x509.CertificateBuilder()
builder = builder.subject_name(x509.Name([
  x509.NameAttribute(NameOID.COMMON_NAME, u'test'),
]))
builder = builder.issuer_name(x509.Name([
  x509.NameAttribute(NameOID.COMMON_NAME, u'test'),
]))
builder = builder.not_valid_before(datetime.datetime.today() - one_day)
builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
builder = builder.serial_number(x509.random_serial_number())
builder = builder.public_key(public_key)
builder = builder.add_extension(
  x509.SubjectAlternativeName(
      [x509.DNSName("@test")]
  ),
  critical=False
)
builder = builder.add_extension(
  x509.BasicConstraints(ca=False, path_length=None), critical=True,
)
certificate = builder.sign(
  private_key=private_key, algorithm=hashes.SHA256(),
  backend=default_backend()
)


def main():
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 16384,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        "sigbutton": True,
        "sigfield": "Signature1",
        "sigandcertify": True,
        "signaturebox": (470, 840, 570, 640),
        "signature": "Dokument podpisany cyfrowo ąćęłńóśżź",
#        "signature_img": "signature_test.png",
        "contact": "mak@trisoft.com.pl",
        "location": "Szczecin",
        "signingdate": date,
        "reason": "Dokument podpisany cyfrowo aą cć eę lł nń oó sś zż zź",
        "password": "1234",
    }

    fname = "pdf.pdf"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, "rb").read()
    data_to_sign = cms.getDataToSign(datau, dct, certificate, [certificate], "sha256")
    
    #### Assume this operation is done without direct key access ####
    signed_hash = private_key.sign(
      data_to_sign[0], # this can also be done pre-hashed
      padding.PKCS1v15(),
      getattr(hashes, data_to_sign[1].upper())()
    )
    #### --- ####
    
    datas = cms.sign(datau, dct, None, certificate, [certificate], "sha256", signed_value_signature=signed_hash)
    fname = fname.replace(".pdf", "-signed-cms.pdf")
    with open(fname, "wb") as fp:
        fp.write(datau)
        fp.write(datas)


main()
