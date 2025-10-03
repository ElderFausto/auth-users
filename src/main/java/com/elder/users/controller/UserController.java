package com.elder.users.controller;

import com.elder.users.dto.UserResponseDTO;
import com.elder.users.entity.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {

  @GetMapping("/me")
  public ResponseEntity<UserResponseDTO> getCurrentUser(@AuthenticationPrincipal User currentUser) {
    UserResponseDTO userResponse = new UserResponseDTO(
        currentUser.getId(),
        currentUser.getUsername(),
        currentUser.getEmail()
    );
    return ResponseEntity.ok(userResponse);
  }
}