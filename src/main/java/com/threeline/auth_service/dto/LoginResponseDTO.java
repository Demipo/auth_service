package com.threeline.auth_service.dto;

import lombok.Data;


/**
 * LoginResponseDTO
 */

@Data
public class LoginResponseDTO extends UserRequestDTO {
    private String token;

    public LoginResponseDTO(String firstName, String lastName, String email, String password, String phone) {
        super(firstName, lastName, email, null, phone);
    }

}
