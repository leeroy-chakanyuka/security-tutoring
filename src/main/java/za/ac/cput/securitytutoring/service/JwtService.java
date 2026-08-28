package za.ac.cput.securitytutoring.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

/**
 * A JWT looks something like this :

         eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ewogICJpc3MiOiAiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tIiwKICAic3ViIjogInVzcl85OD
         c2NTQzMjEiLAogICJhdWQiOiAiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iLAogICJleHAiOiAxNzc2MDAwMDAwLAogICJuYmYiOiAxNzc1OTk2NDA
         wLAogICJpYXQiOiAxNzc1OTk2NDAwLAogICJqdGkiOiAiYjhhMWM5N2YtOTRhMS00MjBhLTgxMjMtYmM5N2U3YjUxYjBmIiwKICAibmFtZSI6ICJ
         BbGV4IFRheWxvciIsCiAgImVtYWlsIjogImFsZXgudGF5bG9yQGV4YW1wbGUuY29tIiwKICAicGljdHVyZSI6ICJodHRwczovL2V4YW1wbGUuY29
         tL2F2YXRhcnMvYWxleC5qcGciLAogICJyb2xlIjogImFkbWluIiwKICAidGVuYW50X2lkIjogIm9yZ180NTY3OCIsCiAgInBlcm1pc3Npb25zIjo
         gWwogICAgInVzZXJzOnJlYWQiLAogICAgInVzZXJzOndyaXRlIgogIF1dfQ.3rP0Xz9GvO0-2x8-6RjE35kL9M1L0-9T2_7rJ0R1U2E

 * when decoded it then turns into an object like this :
         {
         "header": {
         "alg": "HS256",
         "typ": "JWT"
         },
         "payload": {
         "iss": "https://example.com",
         "sub": "usr_987654321",
         "aud": "https://example.com",
         "exp": 1776000000,
         "nbf": 1775996400,
         "iat": 1775996400,
         "jti": "b8a1c97f-94a1-420a-8123-bc97e7b51b0f",
         "name": "Alex Taylor",
         "email": "alex.taylor@example.com",
         "picture": "https://example.com",
         "role": "admin",
         "tenant_id": "org_45678",
         "permissions": [
         "users:read",
         "users:write"
         ]
         },
         "signature": "3rP0Xz9GvO0-2x8-6RjE35kL9M1L0-9T2_7rJ0R1U2E"
         }

 */
@Service
public class JwtService {

    @Value("${JWT_SECRET_KEY}")
    private static String secretKey;

    public String extractUser(String jwtToken){
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.forSigningKey(HS2))

    }

    /* we first create an object to grab the WHOLE jwt*/
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        /*
         * Only gets the payload part of the token
            {
              // --- 1. REGISTERED CLAIMS ---
              "iss": "https://auth.example.com",
              "sub": "usr_987654321",
              "aud": "https://api.example.com",
              "exp": 1776000000,
              "nbf": 1775996400,
              "iat": 1775996400,
              "jti": "b8a1c97f-94a1-420a-8123-bc97e7b51b0f",

              // --- 2. PUBLIC CLAIMS ---
              "name": "Alex Taylor",
              "email": "alex.taylor@example.com",
              "picture": "https://example.com/avatars/alex.jpg",

              // --- 3. PRIVATE CLAIMS ---
              "role": "admin",
              "tenant_id": "org_45678",
              "permissions": [
                "users:read",
                "users:write"
              ]
            }
         */
    }

    /* Helper that decodes our Base64 secret into a key to verify the signature */
    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /* extract a single claim from the token */
    public <T> T extractClaim(String token, Function<Claims, T> resolveClaim){
        Claims claims = extractAllClaims(token);
        return resolveClaim.apply(claims);
    }



}
