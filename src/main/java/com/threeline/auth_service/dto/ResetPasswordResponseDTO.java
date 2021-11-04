package com.threeline.auth_service.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResetPasswordResponseDTO {
    private String plainPassword;
    private String encryptedPassword;
   
}