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

  private Claims extractAllClaims(String token) {
    return Jwts.parser()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();

  }

  private Key getSigningKey() {
    return null;
  }


}
