package com.choutianxius.test_spring_auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.ENC;
import io.jsonwebtoken.Jwts.KEY;
import io.jsonwebtoken.security.AeadAlgorithm;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Date;

@RestController
public class Controller {

    private final SecretKey secretKey;
    private final AeadAlgorithm algorithm;
    private final Map<String, String> users;
    private final Argon2PasswordEncoder passwordEncoder =
            new Argon2PasswordEncoder(16, 32, 1, 19456, 2);

    @Autowired
    public Controller(@Value("${app.jwt.secret-key-b64}") String secretKeyBase64String)
            throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(secretKeyBase64String);
        if (decodedKey.length != 64) {
            throw new Exception("Invalid key length, should be 64 bytes before base64 encoding");
        }
        this.secretKey = new SecretKeySpec(decodedKey, "AES");
        this.algorithm = ENC.A256CBC_HS512;
        this.users = new ConcurrentHashMap<>();
        users.put("user",
                "$argon2id$v=19$m=19456,t=2,p=1$Eva0i9q8Blp+7uL3blPASA$5FzxCZHAYTVXYaam2wZcN1tzTNR5q42v0AumFzzpyqc");
    }

    @GetMapping("/greeting")
    public String greeting(@RequestHeader("Authorization") String authorization) {
        try {
            if (!authorization.startsWith("Bearer ")) {
                throw new AuthException("Authorization header is invalid");
            }
            String token = authorization.substring(7);
            try {
                Claims claims = Jwts.parser().decryptWith(secretKey).build()
                        .parseEncryptedClaims(token).getPayload();
                if (claims.getExpiration().before(new Date())) {
                    throw new AuthException("Token expired");
                }
                String username = claims.getSubject();
                return "Hello, " + username;
            } catch (Exception e) {
                throw new AuthException("Invalid token");
            }
        } catch (AuthException ae) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, ae.getMessage(), ae);
        }
    }

    @PostMapping("/login")
    public Token login(@RequestBody LoginData loginData) {
        try {
            verifyLoginCredentials(loginData.username(), loginData.password());
            String token = Jwts.builder().subject(loginData.username())
                    .encryptWith(secretKey, KEY.DIRECT, algorithm)
                    .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24))
                    .compact();
            return new Token(token);
        } catch (AuthException ae) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ae.getMessage(), ae);
        }
    }

    private void verifyLoginCredentials(String username, String password) throws AuthException {
        if (!users.containsKey(username)) {
            throw new AuthException("Unknown username");
        }
        if (!passwordEncoder.matches(password, users.get(username))) {
            throw new AuthException("Invalid password");
        }
    }
}
