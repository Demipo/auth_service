package com.threeline.auth_service.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;


@Data
@NoArgsConstructor
public class EmailVerificationDTO {
  @Size(max = 5, min = 5, message = "verification code must be 5 digits")
  @NotBlank(message = "code cannot be blank")
  private String code;
  @Email(message = "you must provide a valid email address")
  @NotBlank(message = "email cannot be blank")
  private String email;

  public EmailVerificationDTO(@Size(max = 5, min = 5, message = "verification code must be 5 digits") String code,
      @Email(message = "you must provide a valid email address") @NotBlank(message = "email cannot be blank") String email) {
    this.code = code;
    this.email = email;
  }
}