package com.threeline.auth_service.service;

import com.threeline.auth_service.dto.*;
import com.threeline.auth_service.entity.ForgotPassword;
import com.threeline.auth_service.entity.User;

import javax.servlet.http.HttpServletRequest;

/**
 * AuthService
 */
public interface AuthService {

  UserServiceUser signup(UserServiceUser user);
  void logout(HttpServletRequest request);
  LoginResponseDTO login(LoginRequestDTO user);
  TokenValidationDTO tokenValidation(String token);
  void initiateForgotPassword(ForgotPasswordRequestDTO fg);
  ForgotPassword verifyForgotPasswordCode(VerifyForgotPasswordDTO vfp);
  ResetPasswordResponseDTO resetPassword(ResetPasswordDTO resetPasswordDTO);

  ResetPinResponseDTO resetPin(ResetPasswordDTO resetPasswordDTO);

  void changePassword(ChangePasswordDTO changePasswordDTO, String userEmail);

}
