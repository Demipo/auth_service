package com.threeline.auth_service.controller;

import com.threeline.auth_service.apiresponse.ApiResponse;
import com.threeline.auth_service.dto.*;
import com.threeline.auth_service.security.JwtTokenProvider;
import com.threeline.auth_service.service.AuthService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

/**
 * UserController
 */
@RestController
@RequestMapping("auth")
@Validated
public class AuthController {

  @Autowired
  private AuthService authService;

  @Autowired
  private ModelMapper modelMapper;

  @Autowired
  private JwtTokenProvider jwtTokenProvider;

  @PostMapping("/signup")
  public ResponseEntity<ApiResponse<Object>> signup(@Valid @RequestBody UserServiceUser user) {
    UserServiceUser newUser = authService.signup(user);
    ApiResponse<Object> ar = new ApiResponse<>(HttpStatus.CREATED);
    ar.setMessage("Successfully signed up");
    ar.setData(newUser);
    return new ResponseEntity<>(ar, HttpStatus.CREATED);
  }

  @PostMapping("/login")
  public ResponseEntity<ApiResponse<LoginResponseDTO>> login(@Valid @RequestBody LoginRequestDTO user) {
    LoginResponseDTO loginResponseDTO = authService.login(user);
    ApiResponse<LoginResponseDTO> ar = new ApiResponse<>(HttpStatus.OK);
    ar.setMessage("Login Successful");
    ar.setData(loginResponseDTO);
    return new ResponseEntity<>(ar, ar.getStatus());
  }

  @PostMapping("/token/validation")
  public ResponseEntity<ApiResponse<TokenValidationDTO>> tokenValidation(String token){
    TokenValidationDTO tokenStatus = authService.tokenValidation(token);
    ApiResponse<TokenValidationDTO> ar = new ApiResponse<>(HttpStatus.OK);
    ar.setMessage("Token validated successfully");
    ar.setData(tokenStatus);
    return new ResponseEntity<>(ar, ar.getStatus());
  }

  @PostMapping("/reset/password")
  public ResponseEntity<ApiResponse<ResetPasswordResponseDTO>> resetPassword(ResetPasswordDTO passwordDTO){
    ResetPasswordResponseDTO responseDTO = authService.resetPassword(passwordDTO);
    ApiResponse<ResetPasswordResponseDTO> ar = new ApiResponse<>(HttpStatus.OK);
    ar.setMessage("Password reset successfully");
    ar.setData(responseDTO);
    return new ResponseEntity<>(ar, ar.getStatus());
  }

  @PostMapping("/reset/pin")
  public ResponseEntity<ApiResponse<ResetPinResponseDTO>> resetPin(ResetPasswordDTO passwordDTO){
    ResetPinResponseDTO responseDTO = authService.resetPin(passwordDTO);
    ApiResponse<ResetPinResponseDTO> ar = new ApiResponse<>(HttpStatus.OK);
    ar.setMessage("Password reset successfully");
    ar.setData(responseDTO);
    return new ResponseEntity<>(ar, ar.getStatus());
  }

  @PostMapping("/forgotpassword")
  public ResponseEntity<ApiResponse<?>> login(@Valid @RequestBody ForgotPasswordRequestDTO forgotPasswordRequestDTO) {
    authService.initiateForgotPassword(forgotPasswordRequestDTO);
    ApiResponse<?> ar = new ApiResponse<>(HttpStatus.OK);
    ar.setMessage("Check your email for verification code.");
    return new ResponseEntity<>(ar, ar.getStatus());
  }

  @PostMapping("/forgotpassword/verify")
  public ResponseEntity<ApiResponse<?>> verifyForgotPassword(@Valid @RequestParam VerifyForgotPasswordDTO vfp) {
    authService.verifyForgotPasswordCode(vfp);
    ApiResponse<?> ar = new ApiResponse<>(HttpStatus.OK);
    ar.setMessage("Your code is valid.");
    return new ResponseEntity<>(ar, ar.getStatus());
  }

  @PostMapping("/forgotpassword/changepassword")
  public ResponseEntity<ApiResponse<?>> resetsPassword(@Valid @RequestBody ResetPasswordDTO resetPasswordDTO) {
    authService.resetPassword(resetPasswordDTO);
    ApiResponse<?> ar = new ApiResponse<>(HttpStatus.OK);
    ar.setMessage("Your password has been reset. You can go ahead and login now");
    return new ResponseEntity<>(ar, ar.getStatus());
  }

  @PostMapping("/changepassword")
  @PreAuthorize("hasAuthority('updatePassword')")
  public ResponseEntity<ApiResponse<?>>  changePassword(@Valid @RequestBody ChangePasswordDTO changePasswordDTO, HttpServletRequest request) {
    String loggedInUserEmail = jwtTokenProvider.getEmail(jwtTokenProvider.resolveToken(request));
    authService.changePassword(changePasswordDTO, loggedInUserEmail);
    ApiResponse<?> ar = new ApiResponse<>(HttpStatus.OK);
    ar.setMessage("Your password has been changed successfuly.");
    return new ResponseEntity<>(ar, ar.getStatus());
  }

  @PostMapping("logout")
  public ResponseEntity<ApiResponse<?>> logout(HttpServletRequest request) {
    authService.logout(request);
    ApiResponse<?> response = new ApiResponse<>(HttpStatus.OK);
    response.setMessage("Logout Successful");
    return new ResponseEntity<>(response, response.getStatus());
  }
}