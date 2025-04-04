from mitm import MITM, protocol, CertificateAuthority
import os   
from pathlib import Path
from .middleware import AWSLoggingMiddleware

path = Path(os.path.expanduser('~/.aws-proxy/certs'))
certificate_authority = CertificateAuthority.init(path=path)

mitm = MITM(
    host="127.0.0.1",
    port=8080,
    protocols=[protocol.HTTP],
    middlewares=[AWSLoggingMiddleware],
    certificate_authority = certificate_authority
)
mitm.run()