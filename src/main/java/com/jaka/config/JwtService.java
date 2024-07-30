package com.jaka.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import java.security.Key;

@Service
public class JwtService {
  public String extractUserName(String token) {
    return null;
  }

  // Claims - piece of information asserted about a subject
  private Claims extractAllClaims(String token) {
    return Jwts.parserBuilder() // create a new parser builder
            .setSigningKey(getSigningKey())  // set the key to verify the signature
            .build() // build the parser
            .parseClaimsJws(token) // parse the token
            .getBody(); // get the body of the token
  }

  private Key getSigningKey() {
    return null;
  }


}
