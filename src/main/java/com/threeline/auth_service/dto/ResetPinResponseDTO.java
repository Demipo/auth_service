package com.threeline.auth_service.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResetPinResponseDTO {
    private String plainPin;
    private String encryptedPin;

}