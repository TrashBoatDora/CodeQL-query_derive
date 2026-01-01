//number of apis 91
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("hashlib").getMember("md5") and qn = "hashlib.md5" or
  api = API::moduleImport("hashlib").getMember("sha1") and qn = "hashlib.sha1" or
  api = API::moduleImport("hashlib").getMember("sha224") and qn = "hashlib.sha224" or
  api = API::moduleImport("hashlib").getMember("sha256") and qn = "hashlib.sha256" or
  api = API::moduleImport("hashlib").getMember("sha384") and qn = "hashlib.sha384" or
  api = API::moduleImport("hashlib").getMember("sha512") and qn = "hashlib.sha512" or
  api = API::moduleImport("hashlib").getMember("sha3_224") and qn = "hashlib.sha3_224" or
  api = API::moduleImport("hashlib").getMember("sha3_256") and qn = "hashlib.sha3_256" or
  api = API::moduleImport("hashlib").getMember("sha3_384") and qn = "hashlib.sha3_384" or
  api = API::moduleImport("hashlib").getMember("sha3_512") and qn = "hashlib.sha3_512" or
  api = API::moduleImport("hashlib").getMember("blake2b") and qn = "hashlib.blake2b" or
  api = API::moduleImport("hashlib").getMember("blake2s") and qn = "hashlib.blake2s" or
  api = API::moduleImport("hashlib").getMember("shake_128") and qn = "hashlib.shake_128" or
  api = API::moduleImport("hashlib").getMember("shake_256") and qn = "hashlib.shake_256" or
  api = API::moduleImport("hashlib").getMember("new") and qn = "hashlib.new" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("MD5") and qn = "cryptography.hazmat.primitives.hashes.MD5" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHA1") and qn = "cryptography.hazmat.primitives.hashes.SHA1" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHA224") and qn = "cryptography.hazmat.primitives.hashes.SHA224" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHA256") and qn = "cryptography.hazmat.primitives.hashes.SHA256" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHA384") and qn = "cryptography.hazmat.primitives.hashes.SHA384" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHA512") and qn = "cryptography.hazmat.primitives.hashes.SHA512" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHA3_224") and qn = "cryptography.hazmat.primitives.hashes.SHA3_224" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHA3_256") and qn = "cryptography.hazmat.primitives.hashes.SHA3_256" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHA3_384") and qn = "cryptography.hazmat.primitives.hashes.SHA3_384" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHA3_512") and qn = "cryptography.hazmat.primitives.hashes.SHA3_512" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("BLAKE2b") and qn = "cryptography.hazmat.primitives.hashes.BLAKE2b" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("BLAKE2s") and qn = "cryptography.hazmat.primitives.hashes.BLAKE2s" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHAKE128") and qn = "cryptography.hazmat.primitives.hashes.SHAKE128" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hashes").getMember("SHAKE256") and qn = "cryptography.hazmat.primitives.hashes.SHAKE256" or
  api = API::moduleImport("Crypto").getMember("Hash").getMember("MD2").getMember("new") and qn = "Crypto.Hash.MD2.new" or
  api = API::moduleImport("Crypto").getMember("Hash").getMember("MD4").getMember("new") and qn = "Crypto.Hash.MD4.new" or
  api = API::moduleImport("Crypto").getMember("Hash").getMember("MD5").getMember("new") and qn = "Crypto.Hash.MD5.new" or
  api = API::moduleImport("Crypto").getMember("Hash").getMember("SHA1").getMember("new") and qn = "Crypto.Hash.SHA1.new" or
  api = API::moduleImport("hmac").getMember("new") and qn = "hmac.new" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hmac").getMember("HMAC") and qn = "cryptography.hazmat.primitives.hmac.HMAC" or
  api = API::moduleImport("Crypto").getMember("Hash").getMember("HMAC").getMember("new") and qn = "Crypto.Hash.HMAC.new" or
  api = API::moduleImport("passlib").getMember("hash").getMember("bcrypt") and qn = "passlib.hash.bcrypt" or
  api = API::moduleImport("passlib").getMember("hash").getMember("bcrypt_sha256") and qn = "passlib.hash.bcrypt_sha256" or
  api = API::moduleImport("passlib").getMember("hash").getMember("pbkdf2_sha256") and qn = "passlib.hash.pbkdf2_sha256" or
  api = API::moduleImport("passlib").getMember("hash").getMember("pbkdf2_sha512") and qn = "passlib.hash.pbkdf2_sha512" or
  api = API::moduleImport("passlib").getMember("hash").getMember("sha256_crypt") and qn = "passlib.hash.sha256_crypt" or
  api = API::moduleImport("passlib").getMember("hash").getMember("sha512_crypt") and qn = "passlib.hash.sha512_crypt" or
  api = API::moduleImport("passlib").getMember("hash").getMember("argon2") and qn = "passlib.hash.argon2" or
  api = API::moduleImport("passlib").getMember("hash").getMember("md5_crypt") and qn = "passlib.hash.md5_crypt" or
  api = API::moduleImport("passlib").getMember("hash").getMember("apr_md5_crypt") and qn = "passlib.hash.apr_md5_crypt" or
  api = API::moduleImport("passlib").getMember("hash").getMember("sha1_crypt") and qn = "passlib.hash.sha1_crypt" or
  api = API::moduleImport("passlib").getMember("hash").getMember("des_crypt") and qn = "passlib.hash.des_crypt" or
  api = API::moduleImport("werkzeug").getMember("security").getMember("generate_password_hash") and qn = "werkzeug.security.generate_password_hash" or
  api = API::moduleImport("werkzeug").getMember("security").getMember("check_password_hash") and qn = "werkzeug.security.check_password_hash" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("make_password") and qn = "django.contrib.auth.hashers.make_password" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("check_password") and qn = "django.contrib.auth.hashers.check_password" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("PBKDF2PasswordHasher") and qn = "django.contrib.auth.hashers.PBKDF2PasswordHasher" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("PBKDF2SHA1PasswordHasher") and qn = "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("BCryptSHA256PasswordHasher") and qn = "django.contrib.auth.hashers.BCryptSHA256PasswordHasher" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("BCryptPasswordHasher") and qn = "django.contrib.auth.hashers.BCryptPasswordHasher" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("Argon2PasswordHasher") and qn = "django.contrib.auth.hashers.Argon2PasswordHasher" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("MD5PasswordHasher") and qn = "django.contrib.auth.hashers.MD5PasswordHasher" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("DES").getMember("new") and qn = "Crypto.Cipher.DES.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("DES3").getMember("new") and qn = "Crypto.Cipher.DES3.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("ARC2").getMember("new") and qn = "Crypto.Cipher.ARC2.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("ARC4").getMember("new") and qn = "Crypto.Cipher.ARC4.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("Blowfish").getMember("new") and qn = "Crypto.Cipher.Blowfish.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("AES").getMember("new") and qn = "Crypto.Cipher.AES.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("ChaCha20").getMember("new") and qn = "Crypto.Cipher.ChaCha20.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("ChaCha20_Poly1305").getMember("new") and qn = "Crypto.Cipher.ChaCha20_Poly1305.new" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("AES") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.AES" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("TripleDES") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("ARC4") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.ARC4" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("Blowfish") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("CAST5") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.CAST5" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("IDEA") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.IDEA" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("Camellia") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.Camellia" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("SEED") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.SEED" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("ChaCha20") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESGCM") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESGCM" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESCCM") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESCCM" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESSIV") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESSIV" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("ChaCha20Poly1305") and qn = "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("ECB") and qn = "cryptography.hazmat.primitives.ciphers.modes.ECB" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("CBC") and qn = "cryptography.hazmat.primitives.ciphers.modes.CBC" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("CFB") and qn = "cryptography.hazmat.primitives.ciphers.modes.CFB" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("CFB8") and qn = "cryptography.hazmat.primitives.ciphers.modes.CFB8" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("OFB") and qn = "cryptography.hazmat.primitives.ciphers.modes.OFB" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("CTR") and qn = "cryptography.hazmat.primitives.ciphers.modes.CTR" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("GCM") and qn = "cryptography.hazmat.primitives.ciphers.modes.GCM" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("XTS") and qn = "cryptography.hazmat.primitives.ciphers.modes.XTS" or
  api = API::moduleImport("ssl").getMember("SSLContext").getMember("set_ciphers") and qn = "ssl.SSLContext.set_ciphers" or
  api = API::moduleImport("ssl").getMember("create_default_context") and qn = "ssl.create_default_context" or
  api = API::moduleImport("OpenSSL").getMember("SSL").getMember("Context").getAnInstance().getMember("set_cipher_list") and qn = "OpenSSL.SSL.Context.set_cipher_list" or
  api = API::moduleImport("jwt").getMember("encode") and qn = "jwt.encode" or
  api = API::moduleImport("jwt").getMember("decode") and qn = "jwt.decode" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESCCM") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESCCM" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESCCM").getAnInstance().getMember("encrypt") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESCCM.encrypt" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESCCM").getAnInstance().getMember("decrypt") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESCCM.decrypt" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESSIV").getAnInstance().getMember("encrypt") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESSIV.encrypt" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESSIV").getAnInstance().getMember("decrypt") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESSIV.decrypt" or
  api = API::moduleImport("ssl").getMember("SSLContext").getAnInstance().getMember("set_ciphersuites") and qn = "ssl.SSLContext.set_ciphersuites" or
  api = API::moduleImport("OpenSSL").getMember("SSL").getMember("Context").getAnInstance().getMember("set_tls13_ciphersuites") and qn = "OpenSSL.SSL.Context.set_tls13_ciphersuites" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("SHA1PasswordHasher") and qn = "django.contrib.auth.hashers.SHA1PasswordHasher" or
api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("UnsaltedSHA1PasswordHasher") and qn = "django.contrib.auth.hashers.UnsaltedSHA1PasswordHasher" or
api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("UnsaltedMD5PasswordHasher") and qn = "django.contrib.auth.hashers.UnsaltedMD5PasswordHasher" or
api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("CryptPasswordHasher") and qn = "django.contrib.auth.hashers.CryptPasswordHasher"
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
        