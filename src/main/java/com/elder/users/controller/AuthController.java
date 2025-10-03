package com.elder.users.controller;

import com.elder.users.dto.AuthResponseDTO;
import com.elder.users.dto.LoginDTO;
import com.elder.users.dto.RegisterDTO;
import com.elder.users.dto.UserResponseDTO;
import com.elder.users.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
  private final AuthService authService;

  @PostMapping("/register")
  public ResponseEntity<UserResponseDTO> register(@Valid @RequestBody RegisterDTO request) {
    return ResponseEntity.ok(authService.register(request));
  }

  @PostMapping("/login")
  public ResponseEntity<AuthResponseDTO> login(@RequestBody LoginDTO request) {
    return ResponseEntity.ok(authService.login(request));
  }
}
