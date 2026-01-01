//number of apis 63
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("Crypto").getMember("PublicKey").getMember("RSA").getMember("generate") and qn = "Crypto.PublicKey.RSA.generate" or
  api = API::moduleImport("Crypto").getMember("PublicKey").getMember("DSA").getMember("generate") and qn = "Crypto.PublicKey.DSA.generate" or
  api = API::moduleImport("Crypto").getMember("PublicKey").getMember("ECC").getMember("generate") and qn = "Crypto.PublicKey.ECC.generate" or
  api = API::moduleImport("OpenSSL").getMember("crypto").getMember("PKey").getAnInstance().getMember("generate_key") and qn = "OpenSSL.crypto.PKey.generate_key" or
  api = API::moduleImport("paramiko").getMember("RSAKey").getMember("generate") and qn = "paramiko.RSAKey.generate" or
  api = API::moduleImport("paramiko").getMember("ECDSAKey").getMember("generate") and qn = "paramiko.ECDSAKey.generate" or
  api = API::moduleImport("paramiko").getMember("PKey").getAnInstance().getMember("get_bits") and qn = "paramiko.PKey.get_bits" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("rsa").getMember("generate_private_key") and qn = "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("dsa").getMember("generate_private_key") and qn = "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("ec").getMember("generate_private_key") and qn = "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("ed25519").getMember("Ed25519PrivateKey").getMember("generate") and qn = "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("ed448").getMember("Ed448PrivateKey").getMember("generate") and qn = "cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.generate" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("x25519").getMember("X25519PrivateKey").getMember("generate") and qn = "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("x448").getMember("X448PrivateKey").getMember("generate") and qn = "cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey.generate" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("dh").getMember("generate_parameters") and qn = "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("dh").getMember("DHParameters").getAnInstance().getMember("generate_private_key") and qn = "cryptography.hazmat.primitives.asymmetric.dh.DHParameters.generate_private_key" or
  api = API::moduleImport("paramiko").getMember("Transport").getAnInstance().getMember("get_security_options") and qn = "paramiko.Transport.get_security_options" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("Cipher") and qn = "cryptography.hazmat.primitives.ciphers.Cipher" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("AES") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.AES" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESGCM") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESGCM" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESGCM").getMember("generate_key") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESGCM.generate_key" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESGCMSIV") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESGCMSIV").getMember("generate_key") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV.generate_key" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESCCM") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESCCM" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("ChaCha20Poly1305") and qn = "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("ChaCha20Poly1305").getMember("generate_key") and qn = "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.generate_key" or
  api = API::moduleImport("Crypto").getMember("Protocol").getMember("KDF").getMember("PBKDF2") and qn = "Crypto.Protocol.KDF.PBKDF2" or
  api = API::moduleImport("Crypto").getMember("Protocol").getMember("KDF").getMember("scrypt") and qn = "Crypto.Protocol.KDF.scrypt" or
  api = API::moduleImport("Crypto").getMember("Protocol").getMember("KDF").getMember("HKDF") and qn = "Crypto.Protocol.KDF.HKDF" or
  api = API::moduleImport("hashlib").getMember("pbkdf2_hmac") and qn = "hashlib.pbkdf2_hmac" or
  api = API::moduleImport("hashlib").getMember("scrypt") and qn = "hashlib.scrypt" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("pbkdf2").getMember("PBKDF2HMAC") and qn = "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("scrypt").getMember("Scrypt") and qn = "cryptography.hazmat.primitives.kdf.scrypt.Scrypt" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("hkdf").getMember("HKDF") and qn = "cryptography.hazmat.primitives.kdf.hkdf.HKDF" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("concatkdf").getMember("ConcatKDFHash") and qn = "cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("concatkdf").getMember("ConcatKDFHMAC") and qn = "cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHMAC" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("x963kdf").getMember("X963KDF") and qn = "cryptography.hazmat.primitives.kdf.x963kdf.X963KDF" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("kbkdf").getMember("KBKDFHMAC") and qn = "cryptography.hazmat.primitives.kdf.kbkdf.KBKDFHMAC" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("kbkdf").getMember("KBKDFCMAC") and qn = "cryptography.hazmat.primitives.kdf.kbkdf.KBKDFCMAC" or
  api = API::moduleImport("argon2").getMember("PasswordHasher") and qn = "argon2.PasswordHasher" or
  api = API::moduleImport("argon2").getMember("low_level").getMember("hash_secret") and qn = "argon2.low_level.hash_secret" or
  api = API::moduleImport("passlib").getMember("context").getMember("CryptContext") and qn = "passlib.context.CryptContext" or
  api = API::moduleImport("werkzeug").getMember("security").getMember("generate_password_hash") and qn = "werkzeug.security.generate_password_hash" or
  api = API::moduleImport("bcrypt").getMember("gensalt") and qn = "bcrypt.gensalt" or
  api = API::moduleImport("secrets").getMember("token_bytes") and qn = "secrets.token_bytes" or
  api = API::moduleImport("secrets").getMember("token_hex") and qn = "secrets.token_hex" or
  api = API::moduleImport("secrets").getMember("token_urlsafe") and qn = "secrets.token_urlsafe" or
  api = API::moduleImport("os").getMember("urandom") and qn = "os.urandom" or
  api = API::moduleImport("random").getMember("getrandbits") and qn = "random.getrandbits" or
  api = API::moduleImport("nacl").getMember("public").getMember("PrivateKey").getMember("generate") and qn = "nacl.public.PrivateKey.generate" or
  api = API::moduleImport("nacl").getMember("signing").getMember("SigningKey").getMember("generate") and qn = "nacl.signing.SigningKey.generate" or
  api = API::moduleImport("nacl").getMember("secret").getMember("SecretBox") and qn = "nacl.secret.SecretBox" or
  api = API::moduleImport("ssl").getMember("SSLContext") and qn = "ssl.SSLContext" or
  api = API::moduleImport("ssl").getMember("create_default_context") and qn = "ssl.create_default_context" or
  api = API::moduleImport("ssl").getMember("SSLContext").getMember("set_ciphers") and qn = "ssl.SSLContext.set_ciphers" or
  api = API::moduleImport("ssl").getMember("SSLContext").getMember("minimum_version") and qn = "ssl.SSLContext.minimum_version" or
  api = API::moduleImport("ssl").getMember("SSLContext").getMember("maximum_version") and qn = "ssl.SSLContext.maximum_version" or
  api = API::moduleImport("OpenSSL").getMember("SSL").getMember("Context").getAnInstance().getMember("set_cipher_list") and qn = "OpenSSL.SSL.Context.set_cipher_list" or
  api = API::moduleImport("OpenSSL").getMember("SSL").getMember("Context").getAnInstance().getMember("set_min_proto_version") and qn = "OpenSSL.SSL.Context.set_min_proto_version" or
  api = API::moduleImport("OpenSSL").getMember("SSL").getMember("Context").getAnInstance().getMember("set_max_proto_version") and qn = "OpenSSL.SSL.Context.set_max_proto_version" or
  api = API::moduleImport("jwt").getMember("algorithms").getMember("RSAAlgorithm").getMember("from_jwk") and qn = "jwt.algorithms.RSAAlgorithm.from_jwk" or
  api = API::moduleImport("jwt").getMember("encode") and qn = "jwt.encode" or
  api = API::moduleImport("cryptography").getMember("fernet").getMember("Fernet").getMember("generate_key") and qn = "cryptography.fernet.Fernet.generate_key" or
  api = API::moduleImport("paramiko").getMember("DSSKey").getMember("generate") and qn = "paramiko.DSSKey.generate" or
  api = API::moduleImport("paramiko").getMember("Ed25519Key").getMember("generate") and qn = "paramiko.Ed25519Key.generate" or
  api = API::moduleImport("ssl").getMember("wrap_socket") and qn = "ssl.wrap_socket" or
  api = API::moduleImport("ssl").getMember("SSLContext").getAnInstance().getMember("set_ciphersuites") and qn = "ssl.SSLContext.set_ciphersuites" or
  api = API::moduleImport("OpenSSL").getMember("SSL").getMember("Context").getAnInstance().getMember("set_tls13_ciphersuites") and qn = "OpenSSL.SSL.Context.set_tls13_ciphersuites"
}
from API::Node api, DataFlow::CallCfgNode n, Call c, Function f,
    BasicBlock bb, string qn, string path, int sl, int sc, int el, int ec
where
  targetApi(api, qn) and
  n = api.getACall() and
  c = n.asExpr() and
  bb = n.asCfgNode().getBasicBlock() and
  bb.hasLocationInfo(path, sl, sc, el, ec) and
  f.getBody().contains(c)
select "path: "+ path,"call function: " + c.getLocation().getStartLine()+":"+c.getLocation().getStartColumn()+
"-"+c.getLocation().getEndLine()+":"+c.getLocation().getEndColumn()
,"call in function: " + f.getName()+"@" +f.getLocation().getStartLine()+"-"+f.getLastStatement().getLocation().getEndLine()
, "callee=" + qn, "basic block: "+sl+":"+sc+"-"+el+":"+ec
        