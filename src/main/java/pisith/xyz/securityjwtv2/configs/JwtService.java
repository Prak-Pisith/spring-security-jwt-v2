package pisith.xyz.securityjwtv2.configs;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

// Providing all JWT Functionalities
// Generate, Extract Claims, Expiration Validation, ...

@Service
public class JwtService {

    private static final String JWT_SECRET_KEY = "4ea5cbf37704245c47dbe82778f005b1383a0f257eb579ac50ff47822b371250";
    private static final int TOKEN_EXPIRATION = 1000 * 60 * 24;

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
        return Jwts
                .builder()
                .setClaims(extraClaim)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_EXPIRATION))
                .signWith(getSigninKey(), SignatureAlgorithm.ES256)
                .compact();
    }
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
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
        byte[] keyBytes = Decoders.BASE64.decode(JWT_SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
