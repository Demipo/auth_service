package com.threeline.auth_service.repository;

import com.threeline.auth_service.entity.ForgotPassword;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ForgotPasswordRepository extends JpaRepository<ForgotPassword, Integer> {
  Optional<ForgotPassword> findByEmail(String email);
  Optional<ForgotPassword> findByEmailAndCode(String email, String code);
}