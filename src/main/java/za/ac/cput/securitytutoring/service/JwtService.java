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
 * A JWT looks something like this:
 * <pre>{@code
 * eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ewogICJpc3MiOiAiaHR0cHM6...
 * }</pre>
 * When decoded it turns into an object like this:
 * <pre>{@code
 * {
 *   "header": {
 *     "alg": "HS256",
 *     "typ": "JWT"
 *   },
 *   "payload": {
 *     "iss": "https://example.com",
 *     "sub": "usr_987654321",
 *     ...
 *   },
 *   "signature": "3rP0Xz9GvO0-2x8-6RjE35kL9M1L0-9T2_7rJ0R1U2E"
 * }
 * }</pre>
 */
@Service
public class JwtService {

    @Value("${JWT_SECRET_KEY}")
    private static String secretKey;

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
        /* from the given Base64 string decode and return as bytes*/
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        /* use these bytes to generate a key please */
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Extract a single claim from the token.
     * <ol>
     *     <li>{@code token} : just the raw JWT (string)</li>
     *     <li>a placeholder for a method that WE will give some Claims Object
     *     and return some T, in our codebase one such example is
     *     {@code Claims::getSubject} with the T being a String</li>
     * </ol>
     */
    public <T> T extractClaim(String token, Function<Claims, T> resolveClaim){
        Claims claims = extractAllClaims(token);
        return resolveClaim.apply(claims);
    }

    /**
     * Extract the username (subject) from the token.
     * <p>
     * Uses {@code Claims::getSubject} to say,  in the Claims class,
     * use {@code getSubject()}. Equivalent to the lambda {@code claims -> claims.getSubject()},
     * so we will be using this "method refference" style instead going forward
     */
    public String extractUser(String jwtToken){
        return extractClaim(jwtToken, Claims::getSubject);
    }

    /** pretty simple since this uses a fluent builder, we use the {@code Map<String, Object>}
     *  to make the JSON payload and {@code UserDetails} to add grab username etc  */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24)) /* 24hrs */
                .signWith(getSignInKey())
                .compact();
    }

    /* grab the user from the jwt and see if it fits the current user from userDetails, make sure its not expired */
    public boolean isTokenValid(String token, UserDetails userDetails){
        String user = extractUser(token);
         return (user.equals(userDetails.getUsername()) && isTokenExpired(token));
    }

    public Date extractExpiration(String token){
       return extractClaim(token, Claims::getExpiration);
    }

    /* pretty simple again, grab the expiry from the jwt then see if it expired before today */
    private boolean isTokenExpired(String token) {
        return (extractExpiration(token).before(new Date()));
    }


}
