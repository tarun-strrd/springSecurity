package com.tarun.securitySpring.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY="B4qI0iGotnzuNxjKB1NDShF0NY6zs9aP/F74d1/iTolZp5huk1fY+UxrGZJMKB0e0u2qi3huWIZLZnMXC0R6vCFMGEzevSNvHf4qjOmrnHxtadwQubCejIVFXPPOBFhLf2067TzK4PTrewz4sGwxFPemANvtNmYfJUKGLRgRp8D5PPyzBHV+U8W95c7uiuq7vqKNdOXyTTFPBdrizAR8UlVS5M77/kYUmKLz9HON+nC6TY2KI5AtNFlCOn3vNBCaOHt7F7C8VycFxOUXpU1Tm3DzohgwDfyZfU2SHSdi4fTdRMUQS+uqbdfrxE/Tt1E418j7REWqdH9xMP5DZHPKT1f/RVJYTlMKweF7kRzgCeU=";
    public String extractEmail(String token) {
        return extractClaim(token,Claims::getSubject);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String userName=extractEmail(token);
        return userName.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiry(token).before(new Date());
    }

    private Date extractExpiry(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    public String generateToken(Map<String,Object> extactClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extactClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims=extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
