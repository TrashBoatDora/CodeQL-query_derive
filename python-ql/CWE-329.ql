//number of apis 58
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("AES").getMember("new") and qn = "Crypto.Cipher.AES.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("DES").getMember("new") and qn = "Crypto.Cipher.DES.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("DES3").getMember("new") and qn = "Crypto.Cipher.DES3.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("Blowfish").getMember("new") and qn = "Crypto.Cipher.Blowfish.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("CAST").getMember("new") and qn = "Crypto.Cipher.CAST.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("ARC2").getMember("new") and qn = "Crypto.Cipher.ARC2.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("ChaCha20").getMember("new") and qn = "Crypto.Cipher.ChaCha20.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("ChaCha20_Poly1305").getMember("new") and qn = "Crypto.Cipher.ChaCha20_Poly1305.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("Salsa20").getMember("new") and qn = "Crypto.Cipher.Salsa20.new" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("AES").getMember("MODE_CBC") and qn = "Crypto.Cipher.AES.MODE_CBC" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("AES").getMember("MODE_CFB") and qn = "Crypto.Cipher.AES.MODE_CFB" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("AES").getMember("MODE_OFB") and qn = "Crypto.Cipher.AES.MODE_OFB" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("AES").getMember("MODE_CTR") and qn = "Crypto.Cipher.AES.MODE_CTR" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("AES").getMember("MODE_EAX") and qn = "Crypto.Cipher.AES.MODE_EAX" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("AES").getMember("MODE_GCM") and qn = "Crypto.Cipher.AES.MODE_GCM" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("AES").getMember("MODE_SIV") and qn = "Crypto.Cipher.AES.MODE_SIV" or
  api = API::moduleImport("Crypto").getMember("Cipher").getMember("AES").getMember("MODE_OCB") and qn = "Crypto.Cipher.AES.MODE_OCB" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("Cipher") and qn = "cryptography.hazmat.primitives.ciphers.Cipher" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("AES") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.AES" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("algorithms").getMember("ChaCha20") and qn = "cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("CBC") and qn = "cryptography.hazmat.primitives.ciphers.modes.CBC" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("CFB") and qn = "cryptography.hazmat.primitives.ciphers.modes.CFB" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("CFB8") and qn = "cryptography.hazmat.primitives.ciphers.modes.CFB8" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("OFB") and qn = "cryptography.hazmat.primitives.ciphers.modes.OFB" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("CTR") and qn = "cryptography.hazmat.primitives.ciphers.modes.CTR" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("GCM") and qn = "cryptography.hazmat.primitives.ciphers.modes.GCM" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("modes").getMember("XTS") and qn = "cryptography.hazmat.primitives.ciphers.modes.XTS" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESGCM") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESGCM" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("AESCCM") and qn = "cryptography.hazmat.primitives.ciphers.aead.AESCCM" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("ChaCha20Poly1305") and qn = "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305" or
  api = API::moduleImport("cryptography").getMember("fernet").getMember("Fernet") and qn = "cryptography.fernet.Fernet" or
  api = API::moduleImport("cryptography").getMember("fernet").getMember("Fernet").getMember("generate_key") and qn = "cryptography.fernet.Fernet.generate_key" or
  api = API::moduleImport("nacl").getMember("secret").getMember("SecretBox") and qn = "nacl.secret.SecretBox" or
  api = API::moduleImport("nacl").getMember("secret").getMember("SecretBox").getAnInstance().getMember("encrypt") and qn = "nacl.secret.SecretBox.encrypt" or
  api = API::moduleImport("nacl").getMember("public").getMember("Box") and qn = "nacl.public.Box" or
  api = API::moduleImport("nacl").getMember("public").getMember("Box").getAnInstance().getMember("encrypt") and qn = "nacl.public.Box.encrypt" or
  api = API::moduleImport("nacl").getMember("utils").getMember("random") and qn = "nacl.utils.random" or
  api = API::moduleImport("pyaes").getMember("AESModeOfOperationCBC") and qn = "pyaes.AESModeOfOperationCBC" or
  api = API::moduleImport("pyaes").getMember("AESModeOfOperationCFB") and qn = "pyaes.AESModeOfOperationCFB" or
  api = API::moduleImport("pyaes").getMember("AESModeOfOperationOFB") and qn = "pyaes.AESModeOfOperationOFB" or
  api = API::moduleImport("pyaes").getMember("AESModeOfOperationCTR") and qn = "pyaes.AESModeOfOperationCTR" or
  api = API::moduleImport("M2Crypto").getMember("EVP").getMember("Cipher") and qn = "M2Crypto.EVP.Cipher" or
  api = API::moduleImport("Crypto").getMember("Random").getMember("get_random_bytes") and qn = "Crypto.Random.get_random_bytes" or
  api = API::moduleImport("Crypto").getMember("Random").getMember("new") and qn = "Crypto.Random.new" or
  api = API::moduleImport("os").getMember("urandom") and qn = "os.urandom" or
  api = API::moduleImport("secrets").getMember("token_bytes") and qn = "secrets.token_bytes" or
  api = API::moduleImport("secrets").getMember("token_hex") and qn = "secrets.token_hex" or
  api = API::moduleImport("secrets").getMember("token_urlsafe") and qn = "secrets.token_urlsafe" or
  api = API::moduleImport("secrets").getMember("randbelow") and qn = "secrets.randbelow" or
  api = API::moduleImport("secrets").getMember("choice") and qn = "secrets.choice" or
  api = API::moduleImport("random").getMember("random") and qn = "random.random" or
  api = API::moduleImport("random").getMember("randint") and qn = "random.randint" or
  api = API::moduleImport("random").getMember("randrange") and qn = "random.randrange" or
  api = API::moduleImport("random").getMember("getrandbits") and qn = "random.getrandbits" or
  api = API::moduleImport("random").getMember("randbytes") and qn = "random.randbytes" or
  api = API::moduleImport("numpy").getMember("random").getMember("bytes") and qn = "numpy.random.bytes" or
  api = API::moduleImport("numpy").getMember("random").getMember("randint") and qn = "numpy.random.randint" or
  api = API::moduleImport("uuid").getMember("uuid4") and qn = "uuid.uuid4" or
  api = API::moduleImport("OpenSSL").getMember("rand").getMember("bytes") and qn = "OpenSSL.rand.bytes" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("XChaCha20Poly1305") and qn = "cryptography.hazmat.primitives.ciphers.aead.XChaCha20Poly1305" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("XChaCha20Poly1305").getAnInstance().getMember("encrypt") and qn = "cryptography.hazmat.primitives.ciphers.aead.XChaCha20Poly1305.encrypt" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("ciphers").getMember("aead").getMember("XChaCha20Poly1305").getAnInstance().getMember("decrypt") and qn = "cryptography.hazmat.primitives.ciphers.aead.XChaCha20Poly1305.decrypt"
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
        