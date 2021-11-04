package com.threeline.auth_service.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.threeline.auth_service.apiresponse.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * {JwtTokenFilter} We should use OncePerRequestFilter since we are doing a
 * database call, there is no point in doing this more than once
 */
public class JwtTokenFilter extends OncePerRequestFilter {
  private JwtTokenProvider jwtTokenProvider;

  public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
    this.jwtTokenProvider = jwtTokenProvider;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String token = jwtTokenProvider.resolveToken(request);
    try {
      if (token != null && !jwtTokenProvider.isTokenBlacklisted(token) && jwtTokenProvider.validateToken(token)) {
        Authentication auth = jwtTokenProvider.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(auth);
      } else {
        throw new Exception("FORBIDDEN");
      }
    } catch (Exception e) {
      // this is very important, since it guarantees the user is not authenticated at all
      SecurityContextHolder.clearContext();

      ApiResponse<?> res = new ApiResponse<>(HttpStatus.FORBIDDEN);
      res.setError("FORBIDDEN");
      //set the response headers
      response.setStatus(HttpStatus.FORBIDDEN.value());
      response.setContentType("application/json");

      ObjectMapper mapper = new ObjectMapper();
      PrintWriter out = response.getWriter();
      out.print(mapper.writeValueAsString(res ));
      out.flush();
      return;
    }

    filterChain.doFilter(request, response);
  }

}