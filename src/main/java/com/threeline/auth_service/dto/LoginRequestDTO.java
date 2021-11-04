package com.threeline.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

/**
 * LoginRequestDTO
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequestDTO {
  @NotBlank(message = "Email should not be empty")
  @Email(message = "Should be a valid email address")
  private String email;
  @NotBlank(message = "Password should not be blank")
  private String password;
  @NotBlank(message = "UserId should not be blank")
  private String userId;
  @NotBlank(message = "UserType should not be blank")
  private String userType;

}
