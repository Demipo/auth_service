package com.threeline.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserServiceUser {
    private String firstName;
    private String lastName;
    private String userId;
    private String userType;
    private String password;
}
