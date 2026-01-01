//number of apis 78
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("hashlib").getMember("md5") and qn = "hashlib.md5" or
  api = API::moduleImport("hashlib").getMember("sha1") and qn = "hashlib.sha1" or
  api = API::moduleImport("hashlib").getMember("sha224") and qn = "hashlib.sha224" or
  api = API::moduleImport("hashlib").getMember("sha256") and qn = "hashlib.sha256" or
  api = API::moduleImport("hashlib").getMember("sha384") and qn = "hashlib.sha384" or
  api = API::moduleImport("hashlib").getMember("sha512") and qn = "hashlib.sha512" or
  api = API::moduleImport("hashlib").getMember("blake2b") and qn = "hashlib.blake2b" or
  api = API::moduleImport("hashlib").getMember("blake2s") and qn = "hashlib.blake2s" or
  api = API::moduleImport("hashlib").getMember("sha3_224") and qn = "hashlib.sha3_224" or
  api = API::moduleImport("hashlib").getMember("sha3_256") and qn = "hashlib.sha3_256" or
  api = API::moduleImport("hashlib").getMember("sha3_384") and qn = "hashlib.sha3_384" or
  api = API::moduleImport("hashlib").getMember("sha3_512") and qn = "hashlib.sha3_512" or
  api = API::moduleImport("hashlib").getMember("shake_128") and qn = "hashlib.shake_128" or
  api = API::moduleImport("hashlib").getMember("shake_256") and qn = "hashlib.shake_256" or
  api = API::moduleImport("hashlib").getMember("new") and qn = "hashlib.new" or
  api = API::moduleImport("hmac").getMember("new") and qn = "hmac.new" or
  api = API::moduleImport("hashlib").getMember("pbkdf2_hmac") and qn = "hashlib.pbkdf2_hmac" or
  api = API::moduleImport("hashlib").getMember("scrypt") and qn = "hashlib.scrypt" or
  api = API::moduleImport("bcrypt").getMember("hashpw") and qn = "bcrypt.hashpw" or
  api = API::moduleImport("bcrypt").getMember("gensalt") and qn = "bcrypt.gensalt" or
  api = API::moduleImport("bcrypt").getMember("kdf") and qn = "bcrypt.kdf" or
  api = API::moduleImport("argon2").getMember("PasswordHasher").getAnInstance().getMember("hash") and qn = "argon2.PasswordHasher.hash" or
  api = API::moduleImport("argon2").getMember("PasswordHasher").getAnInstance().getMember("verify") and qn = "argon2.PasswordHasher.verify" or
  api = API::moduleImport("argon2").getMember("low_level").getMember("hash_secret") and qn = "argon2.low_level.hash_secret" or
  api = API::moduleImport("argon2").getMember("low_level").getMember("hash_secret_raw") and qn = "argon2.low_level.hash_secret_raw" or
  api = API::moduleImport("argon2").getMember("low_level").getMember("verify_secret") and qn = "argon2.low_level.verify_secret" or
  api = API::moduleImport("passlib").getMember("hash").getMember("bcrypt").getMember("hash") and qn = "passlib.hash.bcrypt.hash" or
  api = API::moduleImport("passlib").getMember("hash").getMember("bcrypt").getMember("verify") and qn = "passlib.hash.bcrypt.verify" or
  api = API::moduleImport("passlib").getMember("hash").getMember("bcrypt_sha256").getMember("hash") and qn = "passlib.hash.bcrypt_sha256.hash" or
  api = API::moduleImport("passlib").getMember("hash").getMember("bcrypt_sha256").getMember("verify") and qn = "passlib.hash.bcrypt_sha256.verify" or
  api = API::moduleImport("passlib").getMember("hash").getMember("pbkdf2_sha256").getMember("hash") and qn = "passlib.hash.pbkdf2_sha256.hash" or
  api = API::moduleImport("passlib").getMember("hash").getMember("pbkdf2_sha256").getMember("verify") and qn = "passlib.hash.pbkdf2_sha256.verify" or
  api = API::moduleImport("passlib").getMember("hash").getMember("pbkdf2_sha1").getMember("hash") and qn = "passlib.hash.pbkdf2_sha1.hash" or
  api = API::moduleImport("passlib").getMember("hash").getMember("pbkdf2_sha1").getMember("verify") and qn = "passlib.hash.pbkdf2_sha1.verify" or
  api = API::moduleImport("passlib").getMember("hash").getMember("sha256_crypt").getMember("hash") and qn = "passlib.hash.sha256_crypt.hash" or
  api = API::moduleImport("passlib").getMember("hash").getMember("sha256_crypt").getMember("verify") and qn = "passlib.hash.sha256_crypt.verify" or
  api = API::moduleImport("passlib").getMember("hash").getMember("sha512_crypt").getMember("hash") and qn = "passlib.hash.sha512_crypt.hash" or
  api = API::moduleImport("passlib").getMember("hash").getMember("sha512_crypt").getMember("verify") and qn = "passlib.hash.sha512_crypt.verify" or
  api = API::moduleImport("passlib").getMember("hash").getMember("sha1_crypt").getMember("hash") and qn = "passlib.hash.sha1_crypt.hash" or
  api = API::moduleImport("passlib").getMember("hash").getMember("sha1_crypt").getMember("verify") and qn = "passlib.hash.sha1_crypt.verify" or
  api = API::moduleImport("passlib").getMember("hash").getMember("md5_crypt").getMember("hash") and qn = "passlib.hash.md5_crypt.hash" or
  api = API::moduleImport("passlib").getMember("hash").getMember("md5_crypt").getMember("verify") and qn = "passlib.hash.md5_crypt.verify" or
  api = API::moduleImport("passlib").getMember("hash").getMember("argon2").getMember("hash") and qn = "passlib.hash.argon2.hash" or
  api = API::moduleImport("passlib").getMember("hash").getMember("argon2").getMember("verify") and qn = "passlib.hash.argon2.verify" or
  api = API::moduleImport("passlib").getMember("context").getMember("CryptContext").getAnInstance().getMember("hash") and qn = "passlib.context.CryptContext.hash" or
  api = API::moduleImport("passlib").getMember("context").getMember("CryptContext").getAnInstance().getMember("verify") and qn = "passlib.context.CryptContext.verify" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("pbkdf2").getMember("PBKDF2HMAC") and qn = "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("pbkdf2").getMember("PBKDF2HMAC").getAnInstance().getMember("derive") and qn = "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.derive" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("scrypt").getMember("Scrypt") and qn = "cryptography.hazmat.primitives.kdf.scrypt.Scrypt" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("scrypt").getMember("Scrypt").getMember("derive") and qn = "cryptography.hazmat.primitives.kdf.scrypt.Scrypt.derive" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("hkdf").getMember("HKDF") and qn = "cryptography.hazmat.primitives.kdf.hkdf.HKDF" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("hkdf").getMember("HKDF").getAnInstance().getMember("derive") and qn = "cryptography.hazmat.primitives.kdf.hkdf.HKDF.derive" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("concatkdf").getMember("ConcatKDFHash") and qn = "cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("kdf").getMember("concatkdf").getMember("ConcatKDFHash").getAnInstance().getMember("derive") and qn = "cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash.derive" or
  api = API::moduleImport("werkzeug").getMember("security").getMember("generate_password_hash") and qn = "werkzeug.security.generate_password_hash" or
  api = API::moduleImport("werkzeug").getMember("security").getMember("check_password_hash") and qn = "werkzeug.security.check_password_hash" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("make_password") and qn = "django.contrib.auth.hashers.make_password" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("check_password") and qn = "django.contrib.auth.hashers.check_password" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("PBKDF2PasswordHasher").getAnInstance().getMember("encode") and qn = "django.contrib.auth.hashers.PBKDF2PasswordHasher.encode" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("BCryptPasswordHasher").getAnInstance().getMember("encode") and qn = "django.contrib.auth.hashers.BCryptPasswordHasher.encode" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("ScryptPasswordHasher").getAnInstance().getMember("encode") and qn = "django.contrib.auth.hashers.ScryptPasswordHasher.encode" or
  api = API::moduleImport("django").getMember("contrib").getMember("auth").getMember("hashers").getMember("Argon2PasswordHasher").getAnInstance().getMember("encode") and qn = "django.contrib.auth.hashers.Argon2PasswordHasher.encode" or
  api = API::moduleImport("flask_bcrypt").getMember("Bcrypt").getAnInstance().getMember("generate_password_hash") and qn = "flask_bcrypt.Bcrypt.generate_password_hash" or
  api = API::moduleImport("flask_bcrypt").getMember("Bcrypt").getAnInstance().getMember("check_password_hash") and qn = "flask_bcrypt.Bcrypt.check_password_hash" or
  api = API::moduleImport("nacl").getMember("pwhash").getMember("argon2id").getMember("str") and qn = "nacl.pwhash.argon2id.str" or
  api = API::moduleImport("nacl").getMember("pwhash").getMember("argon2id").getMember("verify") and qn = "nacl.pwhash.argon2id.verify" or
  api = API::moduleImport("scrypt").getMember("hash") and qn = "scrypt.hash" or
  api = API::moduleImport("pyscrypt").getMember("hash") and qn = "pyscrypt.hash" or
  api = API::moduleImport("crypt").getMember("crypt") and qn = "crypt.crypt" or
  api = API::moduleImport("crypt").getMember("mksalt") and qn = "crypt.mksalt" or
  api = API::moduleImport("secrets").getMember("token_bytes") and qn = "secrets.token_bytes" or
  api = API::moduleImport("secrets").getMember("token_hex") and qn = "secrets.token_hex" or
  api = API::moduleImport("secrets").getMember("token_urlsafe") and qn = "secrets.token_urlsafe" or
  api = API::moduleImport("os").getMember("urandom") and qn = "os.urandom" or
  api = API::moduleImport("uuid").getMember("uuid4") and qn = "uuid.uuid4" or
  api = API::moduleImport("random").getMember("getrandbits") and qn = "random.getrandbits" or
  api = API::moduleImport("random").getMember("randbytes") and qn = "random.randbytes" or
  api = API::moduleImport("blake3").getMember("blake3") and qn = "blake3.blake3" or
  api = API::moduleImport("werkzeug").getMember("security").getMember("pbkdf2_hex") and qn = "werkzeug.security.pbkdf2_hex" or
  api = API::moduleImport("nacl").getMember("pwhash").getMember("scryptsalsa208sha256").getMember("str") and qn = "nacl.pwhash.scryptsalsa208sha256.str" or
  api = API::moduleImport("nacl").getMember("pwhash").getMember("scryptsalsa208sha256").getMember("verify") and qn = "nacl.pwhash.scryptsalsa208sha256.verify" or
  api = API::moduleImport("blake3").getMember("hash") and qn = "blake3.hash"
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
        