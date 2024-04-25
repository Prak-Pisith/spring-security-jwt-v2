package pisith.xyz.securityjwtv2.configs;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

// Providing all JWT Functionalities
// Generate, Extract Claims, Expiration Validation, ...

@Service
public class JwtService {

//    private static final String JWT_SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
//    private static final int TOKEN_EXPIRATION = 86400000;

    @Value("${spring.application.security.jwt.secret}")
    private String jwtSecretKey;
    @Value("${spring.application.security.jwt.expiration}")
    private int tokenExpiration;
    @Value("${spring.application.security.jwt.refresh-token.expiration}")
    private long refreshTokenExpiration;

    public String extractUsername (String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim (String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(
        Map<String, Objects> extraClaim,
        UserDetails userDetails
    ) {
        return buildToken(extraClaim, userDetails, tokenExpiration);
    }
    public String generateToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, tokenExpiration);
    }

    public String generateRefreshToken(
            UserDetails userDetails
    ) {
        return buildToken(new HashMap<>(), userDetails, refreshTokenExpiration);
    }

    private String buildToken(
            Map<String, Objects> extraClaim,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaim)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid (String token, UserDetails userDetails) {
        final String username = extractUsername (token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    public boolean isTokenExpired (String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration (String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Get all Claims inside JWT Token
    public Claims extractAllClaims (String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
