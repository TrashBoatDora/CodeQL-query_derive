//number of apis 36
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("jwt").getMember("decode") and qn = "jwt.decode" or
  api = API::moduleImport("jwt").getMember("get_unverified_header") and qn = "jwt.get_unverified_header" or
  api = API::moduleImport("jwt").getMember("PyJWKClient").getAnInstance().getMember("get_signing_key_from_jwt") and qn = "jwt.PyJWKClient.get_signing_key_from_jwt" or
  api = API::moduleImport("jose").getMember("jwt").getMember("decode") and qn = "jose.jwt.decode" or
  api = API::moduleImport("jose").getMember("jwt").getMember("get_unverified_header") and qn = "jose.jwt.get_unverified_header" or
  api = API::moduleImport("jose").getMember("jwt").getMember("get_unverified_claims") and qn = "jose.jwt.get_unverified_claims" or
  api = API::moduleImport("jose").getMember("jws").getMember("verify") and qn = "jose.jws.verify" or
  api = API::moduleImport("authlib").getMember("jose").getMember("jwt").getMember("decode") and qn = "authlib.jose.jwt.decode" or
  api = API::moduleImport("authlib").getMember("jose").getMember("JsonWebToken").getAnInstance().getMember("decode") and qn = "authlib.jose.JsonWebToken.decode" or
  api = API::moduleImport("jwcrypto").getMember("jws").getMember("JWS").getAnInstance().getMember("verify") and qn = "jwcrypto.jws.JWS.verify" or
  api = API::moduleImport("itsdangerous").getMember("Serializer").getAnInstance().getMember("loads") and qn = "itsdangerous.Serializer.loads" or
  api = API::moduleImport("itsdangerous").getMember("URLSafeSerializer").getAnInstance().getMember("loads") and qn = "itsdangerous.URLSafeSerializer.loads" or
  api = API::moduleImport("itsdangerous").getMember("URLSafeTimedSerializer").getAnInstance().getMember("loads") and qn = "itsdangerous.URLSafeTimedSerializer.loads" or
  api = API::moduleImport("itsdangerous").getMember("Signer").getAnInstance().getMember("unsign") and qn = "itsdangerous.Signer.unsign" or
  api = API::moduleImport("itsdangerous").getMember("TimestampSigner").getAnInstance().getMember("unsign") and qn = "itsdangerous.TimestampSigner.unsign" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("rsa").getMember("RSAPublicKey").getAnInstance().getMember("verify") and qn = "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verify" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("dsa").getMember("DSAPublicKey").getAnInstance().getMember("verify") and qn = "cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey.verify" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("ec").getMember("EllipticCurvePublicKey").getAnInstance().getMember("verify") and qn = "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("ed25519").getMember("Ed25519PublicKey").getAnInstance().getMember("verify") and qn = "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.verify" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("asymmetric").getMember("ed448").getMember("Ed448PublicKey").getAnInstance().getMember("verify") and qn = "cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey.verify" or
  api = API::moduleImport("cryptography").getMember("hazmat").getMember("primitives").getMember("hmac").getMember("HMAC").getMember("verify") and qn = "cryptography.hazmat.primitives.hmac.HMAC.verify" or
  api = API::moduleImport("hmac").getMember("compare_digest") and qn = "hmac.compare_digest" or
  api = API::moduleImport("secrets").getMember("compare_digest") and qn = "secrets.compare_digest" or
  api = API::moduleImport("OpenSSL").getMember("crypto").getMember("X509StoreContext").getAnInstance().getMember("verify_certificate") and qn = "OpenSSL.crypto.X509StoreContext.verify_certificate" or
  api = API::moduleImport("nacl").getMember("signing").getMember("VerifyKey").getAnInstance().getMember("verify") and qn = "nacl.signing.VerifyKey.verify" or
  api = API::moduleImport("josepy").getMember("jws").getMember("JWS").getAnInstance().getMember("verify") and qn = "josepy.jws.JWS.verify" or
  api = API::moduleImport("signxml").getMember("XMLVerifier").getAnInstance().getMember("verify") and qn = "signxml.XMLVerifier.verify" or
  api = API::moduleImport("xmlsec").getMember("SignatureContext").getMember("verify") and qn = "xmlsec.SignatureContext.verify" or
  api = API::moduleImport("google").getMember("oauth2").getMember("id_token").getMember("verify_oauth2_token") and qn = "google.oauth2.id_token.verify_oauth2_token" or
  api = API::moduleImport("google").getMember("oauth2").getMember("id_token").getMember("verify_firebase_token") and qn = "google.oauth2.id_token.verify_firebase_token" or
  api = API::moduleImport("google").getMember("auth").getMember("jwt").getMember("decode") and qn = "google.auth.jwt.decode" or
  api = API::moduleImport("firebase_admin").getMember("auth").getMember("verify_id_token") and qn = "firebase_admin.auth.verify_id_token" or
  api = API::moduleImport("dkim").getMember("verify") and qn = "dkim.verify" or
  api = API::moduleImport("dkim").getMember("DKIM").getAnInstance().getMember("verify") and qn = "dkim.DKIM.verify" or
  api = API::moduleImport("gnupg").getMember("GPG").getAnInstance().getMember("verify") and qn = "gnupg.GPG.verify" or
  api = API::moduleImport("pgpy").getMember("PGPKey").getAnInstance().getMember("verify") and qn = "pgpy.PGPKey.verify" or
  api = API::moduleImport("authlib").getMember("jose").getMember("JsonWebSignature").getAnInstance().getMember("verify") and qn = "authlib.jose.JsonWebSignature.verify" or
  api = API::moduleImport("OpenSSL").getMember("crypto").getMember("verify") and qn = "OpenSSL.crypto.verify" or
  api = API::moduleImport("google").getMember("auth").getMember("jwt").getMember("decode_verify") and qn = "google.auth.jwt.decode_verify"
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
        