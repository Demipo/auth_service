package com.threeline.auth_service.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.validation.constraints.Email;
import javax.validation.constraints.Future;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ForgotPassword {
  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  protected Integer id;

  @NotBlank(message = "email should not be empty")
  @Email(message = "email should be a valid email address")
  private String email;
  @NotBlank(message = "code should not be blank")
  @Size(min = 5, max = 5, message = "code should be 5 digits")
  private String code;

  @Future
  private LocalDateTime validity;

  private boolean isValid;

}