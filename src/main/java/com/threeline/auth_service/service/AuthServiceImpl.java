package com.threeline.auth_service.service;


import com.threeline.auth_service.dto.*;
import com.threeline.auth_service.entity.ForgotPassword;
import com.threeline.auth_service.entity.TokenBlacklist;
import com.threeline.auth_service.entity.User;
import com.threeline.auth_service.exceptions.CustomException;
import com.threeline.auth_service.repository.ForgotPasswordRepository;
import com.threeline.auth_service.repository.TokenBlacklistRepository;
import com.threeline.auth_service.repository.UserRepository;
import com.threeline.auth_service.security.AES;
import com.threeline.auth_service.security.JwtTokenProvider;
import org.apache.commons.lang3.RandomStringUtils;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * UserService
 */
@Service
public class AuthServiceImpl implements AuthService {

    private UserRepository userRepository;
    private ForgotPasswordRepository forgotPasswordRepository;
    private PasswordEncoder passwordEncoder;
    private JwtTokenProvider jwtTokenProvider;
    private TokenBlacklistRepository tokenBlacklistRepository;
    private AuthenticationManager authenticationManager;

    //TODO: Reimplement with Redis
    private Map<String, List<String>> codeHolder;
    private ModelMapper modelMapper;

    @Autowired
    public AuthServiceImpl(UserRepository userRepository, AuthenticationManager authenticationManager,
                           JwtTokenProvider jwtTokenProvider, PasswordEncoder passwordEncoder,
                           ForgotPasswordRepository forgotPasswordRepository,
                           TokenBlacklistRepository tokenBlacklistRepository, AES aes) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.forgotPasswordRepository = forgotPasswordRepository;
        this.tokenBlacklistRepository = tokenBlacklistRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public UserServiceUser signup(UserServiceUser serviceUser) {
        User user = new User();
        String userId = generateUserId(serviceUser.getFirstName(), serviceUser.getLastName());
        while(userRepository.existsByUserId(userId)){
            userId = generateUserId(serviceUser.getFirstName(), serviceUser.getLastName());
        }
        serviceUser.setUserId(userId);

        //TODO: Call the User Service to create user
        UserServiceUser savedServiceUser = new UserServiceUser(); // change to response from the user service

        if(Objects.nonNull(savedServiceUser)){
            user = modelMapper.map(savedServiceUser, User.class);
            user.setPassword(passwordEncoder.encode(serviceUser.getPassword()));
            userRepository.save(user);
        }else{
            throw new CustomException("User cannot be created", HttpStatus.UNPROCESSABLE_ENTITY);
        }
        return savedServiceUser;
    }

    public LoginResponseDTO login(LoginRequestDTO user) {

        String username = user.getEmail();
        String password = user.getPassword();

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

            User loggedInUser = userRepository.findByUserName(username).orElseThrow(() -> new CustomException("Invalid username/password supplied...", HttpStatus.UNPROCESSABLE_ENTITY));

            String token = jwtTokenProvider.createToken(username);
            LoginResponseDTO responseDTO = new LoginResponseDTO(
                    loggedInUser.getFirstName(), loggedInUser.getLastName(),
                    loggedInUser.getEmail(), null, loggedInUser.getPhone());
            responseDTO.setToken(token);
            return responseDTO;
        } catch (AuthenticationException e) {
            throw new CustomException("Invalid username/password supplied", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    @Override
    public TokenValidationDTO tokenValidation(String token) {
        TokenValidationDTO tvd = new TokenValidationDTO();
        Boolean status = (jwtTokenProvider.validateToken(token) && !jwtTokenProvider.isTokenExpired(token)) ? true : false;
        tvd.setTokenStatus(status);
        return tvd;
    }

    @Override
    public ResetPasswordResponseDTO resetPassword(ResetPasswordDTO resetPasswordDTO) {
        String plainPassword = RandomStringUtils.randomAlphabetic(8);
        return new ResetPasswordResponseDTO(plainPassword, passwordEncoder.encode(plainPassword));

        //TODO: Yet to decide if this service is called first or another service redirects here
        //TODO: Call the User Service to reset the encrypted password and send user a mail.
    }

    @Override
    public ResetPinResponseDTO resetPin(ResetPasswordDTO resetPasswordDTO) {
        String plainPin = RandomStringUtils.randomNumeric(4);
        return new ResetPinResponseDTO(plainPin, passwordEncoder.encode(plainPin));
    }



    @Override
    public void initiateForgotPassword(ForgotPasswordRequestDTO fg) {

        String code = RandomStringUtils.randomNumeric(5);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String nowPlus15minutes = formatter.format(LocalDateTime.now().plusMinutes(15));

        if(codeHolder.containsKey(fg.getEmail())){
            codeHolder.replace(fg.getEmail(), Arrays.asList(code, nowPlus15minutes)); }
        else{ codeHolder.put(fg.getEmail(), Arrays.asList(code, nowPlus15minutes));}

        CompletableFuture.supplyAsync(() -> {
            // TODO: Invoke the mail/sms service asynchronously
            return null;
        });
    }

    @Override
    public ForgotPassword verifyForgotPasswordCode(VerifyForgotPasswordDTO vfp) {

        List<String> codeHolderValue = codeHolder.get(vfp.getEmail());
        DateTimeFormatter formatter = DateTimeFormatter.ISO_DATE_TIME;
        LocalDateTime codeDate = LocalDateTime.parse(codeHolderValue.get(1), formatter);

        if(!codeHolderValue.isEmpty()) {
            if (!codeDate.isBefore(LocalDateTime.now())) {
                throw new CustomException("Code has expired", HttpStatus.BAD_REQUEST); }
            if (!codeHolderValue.get(0).equals(vfp.getCode())) {
                throw new CustomException("Code is incorrect", HttpStatus.BAD_REQUEST);
            }
        }

        return new ForgotPassword();
    }


    @Override
    public void changePassword(ChangePasswordDTO changePasswordDTO, String userEmail) {
        User user = userRepository.findByUserName(userEmail).orElseThrow(() -> new CustomException("You are not authorized", HttpStatus.UNAUTHORIZED));
        user.setPassword(passwordEncoder.encode(changePasswordDTO.getPassword()));
        userRepository.save(user);
    }

    @Override
    public void logout(HttpServletRequest request) {
        String token = jwtTokenProvider.resolveToken(request);
        String email = jwtTokenProvider.getEmail(token);
        TokenBlacklist tokenBlacklist = new TokenBlacklist();
        tokenBlacklist.setToken(token);
        tokenBlacklist.setEmail(email);
        tokenBlacklistRepository.save(tokenBlacklist);
    }

    private String generateUserId(String firstName, String lastName) {
        String randomNum = RandomStringUtils.randomNumeric(4);
        return (firstName.substring(0,2) + lastName.substring(0,2) + randomNum).toUpperCase();
    }
}
