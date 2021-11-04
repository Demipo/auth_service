package com.threeline.auth_service.security;

import com.threeline.auth_service.entity.User;
import com.threeline.auth_service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


/**
 * MyUserDetails
 */
@Service
public class MyUserDetails implements UserDetailsService {

  @Autowired
  private UserRepository userRepository;

  private UserDetails GetDetails(String username, String password) {
    return org.springframework.security.core.userdetails.User
            .withUsername(username)
            .password(password)
            .accountExpired(false).accountLocked(false)
            .credentialsExpired(false)
            .disabled(false)
            .build();
  }


  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUserName(username).orElseThrow(() -> new  UsernameNotFoundException("User with '" + username + "' not found"));
    UserDetails ud = GetDetails(username, user.getPassword());
    return ud;
  }

}