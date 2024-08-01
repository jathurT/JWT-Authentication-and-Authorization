package com.jaka.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

  @Value("${application.security.jwt.secret-key}")
  private String secretKey;// secret key

  public String extractUserName(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claim = extractAllClaims(token);
    return claimsResolver.apply(claim); // extract the claim from the claims object and return needed value
  }

  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUserName(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }

  private boolean isTokenExpired(String token) {
    return extractAllClaims(token).getExpiration().before(new Date());
  }

  public String generateToken(UserDetails userDetails) {
    return generateToken(new HashMap<>(), userDetails);
  }

  public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
    return Jwts.builder() // create a new builder
            .setClaims(extraClaims) // set the claims
            .setSubject(userDetails.getUsername()) // set the subject
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
            .signWith(getSigningKey(), SignatureAlgorithm.HS256) // sign with the key
            .compact(); // build the token and return it
  }

  // Claims - piece of information asserted about a subject
  private Claims extractAllClaims(String token) {
    return Jwts.parserBuilder() // create a new parser builder
            .setSigningKey(getSigningKey())  // set the key to verify the signature
            .build() // build the parser
            .parseClaimsJws(token) // validate the token and return the JWS(JSON Web Signature)
            .getBody(); // get the body of the token
  }

  private Key getSigningKey() {
    byte[] secretBytes = Decoders.BASE64.decode(secretKey); // decode the secret key
    return Keys.hmacShaKeyFor(secretBytes); // create a new key from the secret key
  }


}
