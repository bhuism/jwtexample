package nl.example.jwtgenerator;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;


public class Main {

    public static String convertToPEM(RSAPublicKey publicKey) {
        String base64Encoded = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(publicKey.getEncoded());

        // Wrap with PEM header and footer
        String pem = "-----BEGIN PUBLIC KEY-----\n" +
            base64Encoded + "\n" +
            "-----END PUBLIC KEY-----";

        return pem;
    }

    public static String convertToPEM(PrivateKey privateKey) {
        String base64Encoded = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(privateKey.getEncoded());

        // Wrap with PEM header and footer
        String pem = "-----BEGIN PRIVATE KEY-----\n" +
            base64Encoded + "\n" +
            "-----END PRIVATE KEY-----";

        return pem;
    }

    public static void main(String[] args) throws Exception {

        // 1. Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        System.out.println("Private key:\n" + convertToPEM(privateKey));

        System.out.println("Public key:\n" + convertToPEM(publicKey));

        // 2. Create JWT claims
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("1234567890") // hier zou het BSN typisch in kunnen
            .issuer("v1.digid.nl")
            .expirationTime(new Date(new Date().getTime() + 60 * 1000)) // expires in 60 seconds
            .build();

        System.out.println("JWT claims:\n" + claims.toString());

        // 3. Sign the JWT with the RSA private key
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
        SignedJWT signedJWT = new SignedJWT(jwsHeader, claims);
        RSASSASigner signer = new RSASSASigner(privateKey);
        signedJWT.sign(signer);

        System.out.println("Signed, unencryppted JWT:\n" + signedJWT.serialize());

        // 4. Encrypt the signed JWT
        JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
            .contentType("JWT") // nested JWT
            .build();
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(signedJWT));
        RSAEncrypter encrypter = new RSAEncrypter(publicKey);
        jweObject.encrypt(encrypter);

        // 5. Serialize the encrypted JWT
        String jwtString = jweObject.serialize();
        System.out.println("Encrypted JWT:\n" + jwtString);

        // -----------------------------
        // VALIDATION + DECRYPTION
        // -----------------------------

        // 6. Parse the JWT
        JWEObject parsedJweObject = JWEObject.parse(jwtString);

        // 7. Decrypt using the RSA private key
        RSADecrypter decrypter = new RSADecrypter(privateKey);
        parsedJweObject.decrypt(decrypter);

        // 8. Extract and verify the signed JWT
        SignedJWT parsedSignedJWT = parsedJweObject.getPayload().toSignedJWT();

        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        if (parsedSignedJWT.verify(verifier)) {
            System.out.println("Signature verified!");

            JWTClaimsSet verifiedClaims = parsedSignedJWT.getJWTClaimsSet();
            System.out.println("Decrypted & verified JWT claims:");
            System.out.println("Subject: " + verifiedClaims.getSubject());
        } else {
            System.out.println("Signature verification failed!");
        }
    }
}
