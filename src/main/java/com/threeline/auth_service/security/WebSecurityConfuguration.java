package com.threeline.auth_service.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

/**
 * WebSecurityConfuguration Overrides the spring security configuration by
 * extending the abstract class WebSecurityConfigurerAdapter
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfuguration extends WebSecurityConfigurerAdapter {

  @Autowired
  private JwtTokenProvider jwtTokenProvider;

  @Autowired
  MyUserDetails myUserDetails;

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring().antMatchers("/auth/signup").antMatchers("/auth/signup/verify/email").antMatchers("/auth/login")
        .antMatchers("/auth/forgotpassword").antMatchers("/auth/forgotpassword/changepassword")
        .antMatchers("/swagger-ui/**").antMatchers("/v3/api-docs").antMatchers("/swagger-ui.html")
        .antMatchers("/api-doc").antMatchers("/api-doc.yaml").antMatchers("/v3/api-docs/swagger-config")
        .antMatchers("/home").antMatchers("/actuator/**");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // We configure security for web pages...

    // Disable CSRF (cross site request forgery)
    // enabled by default
    http.csrf().disable();

    // No session will be created or used by spring security
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    http.authorizeRequests().anyRequest().authenticated();

    http.exceptionHandling().accessDeniedPage("/api/v1/auth/login");

    http.apply(new JwtTokenFilterConfigurer(jwtTokenProvider));
  }

  @Override
  protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
    authenticationManagerBuilder.userDetailsService(myUserDetails);
  }

  @Bean
  public AuthenticationManager customAuthenticationManager() throws Exception {
    return authenticationManager();
  }
}