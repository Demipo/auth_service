package com.threeline.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class VerifyForgotPasswordDTO {
  @NotBlank(message = "email should not be empty")
  @Email(message = "email should be a valid email address")
  private String email;

  @NotBlank
  @Size(min = 5, max = 5, message = "code should 5 digits")
  private String code;

}