package com.app.SpringSecurityApp.controller;

import com.app.SpringSecurityApp.controller.dto.AuthCreateUserRequest;
import com.app.SpringSecurityApp.controller.dto.AuthLoginRequest;
import com.app.SpringSecurityApp.controller.dto.AuthResponse;
import com.app.SpringSecurityApp.service.UserDetailServiceImpl;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private UserDetailServiceImpl userDetailServiceImpl;

    public AuthenticationController(UserDetailServiceImpl userDetailServiceImpl) {
        this.userDetailServiceImpl = userDetailServiceImpl;
    }

    @PostMapping("/sign-up")
    public ResponseEntity<AuthResponse> register(@RequestBody @Valid AuthCreateUserRequest authCreateUser) {
        return new ResponseEntity<>(this.userDetailServiceImpl.createUser(authCreateUser), HttpStatus.CREATED);
    }

    @PostMapping("/log-in")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid AuthLoginRequest userRequest) {
        return new ResponseEntity<>(this.userDetailServiceImpl.loginUser(userRequest), HttpStatus.OK);
    }

}
