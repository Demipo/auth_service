package com.threeline.auth_service.repository;

import com.threeline.auth_service.entity.TokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Integer> {
  boolean existsByToken(String token);
}
