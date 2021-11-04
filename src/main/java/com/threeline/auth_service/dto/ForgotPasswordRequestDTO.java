package com.threeline.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class ForgotPasswordRequestDTO {
  @NotBlank(message = "email should not be empty")
  @Email(message = "email should be a valid email address")
  private String email;
  @NotBlank(message = "email should not be empty")
  private String phone;

}