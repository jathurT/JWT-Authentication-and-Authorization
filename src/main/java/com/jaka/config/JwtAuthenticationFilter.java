package com.jaka.config;


import com.jaka.user.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter { // filter that will intercept every request
  private final JwtService jwtService;

  private final UserDetailsService userDetailService;

  @Override
  protected void doFilterInternal(@NonNull HttpServletRequest request,
                                  @NonNull HttpServletResponse response,
                                  @NonNull FilterChain filterChain
  ) throws ServletException, IOException {

    final String authorizationHeader = request.getHeader("Authorization");
    final String jwt;
    final String userEmail;

    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      jwt = authorizationHeader.substring(7);
      userEmail = jwtService.extractUserName(jwt);
      if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) { // if the user is not already authenticated
        UserDetails userDetails = this.userDetailService.loadUserByUsername(userEmail); // load the user by email
        if (jwtService.isTokenValid(jwt, userDetails)) {
          UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                  userDetails, null, userDetails.getAuthorities()
          );
          authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // set the details
          SecurityContextHolder.getContext().setAuthentication(authenticationToken); // set the authentication
        }
      }
      filterChain.doFilter(request, response); // continue to the next filter
    } else {
      filterChain.doFilter(request, response); // continue to the next filter
      return;
    }
  }
}
