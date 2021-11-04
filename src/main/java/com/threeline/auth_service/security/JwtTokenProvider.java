package com.threeline.auth_service.security;
;
import com.threeline.auth_service.entity.User;
import com.threeline.auth_service.repository.TokenBlacklistRepository;
import com.threeline.auth_service.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

/**
 * JwtTokenProvider
 */
@Component
public class JwtTokenProvider {

  @Value("${api.security.jwt.token.secret-key:secret-key}")
  private String secretKey;

  @Value("${api.security.jwt.token.expire-length:86400000}")
  private long validityInMilliseconds = 86400000;

  @Autowired
  private UserDetailsService myUserDetails;

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private TokenBlacklistRepository tokenBlacklistRepository;

  @PostConstruct
  public void init() {
    secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
  }

  protected String generateToken(String subject, Long validityPeriod) {
    Claims claims = Jwts.claims().setSubject(subject);
    Date now = new Date();
    Date validity = new Date(now.getTime() + validityPeriod);

    return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
  }

  public String createToken(String username) {
    return generateToken(username, validityInMilliseconds);
  }

  public String resolveToken(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7);
    }
    return null;
  }

  public boolean validateToken(String token) {
    try {
      Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
      return true;
    } catch (JwtException | IllegalArgumentException e) {
      return false;
    }
  }

  public Authentication getAuthentication(String token) {
    UserDetails userDetails = myUserDetails.loadUserByUsername(getEmail(token));
    return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
  }

  public String getEmail(String token) {
    return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
  }

  private Claims getAllClaims(String token) {
    return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
  }

  public boolean isTokenBlacklisted(String token) {
    return tokenBlacklistRepository.existsByToken(token);
  }

  public Boolean isTokenExpired(String token) {
    return getAllClaims(token).getExpiration().before(new Date());
  }

  public Optional<User> resolveUser(HttpServletRequest request){
    String token = this.resolveToken(request);
    String email = this.getEmail(token);
    Optional<User> user = userRepository.findByUserName(email);
    return user;
  }
}
