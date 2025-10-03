package com.elder.users.service;

import com.elder.users.dto.AuthResponseDTO;
import com.elder.users.dto.LoginDTO;
import com.elder.users.dto.RegisterDTO;
import com.elder.users.dto.UserResponseDTO;
import com.elder.users.entity.User;
import com.elder.users.repository.UserRepository;
import com.elder.users.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public UserResponseDTO register(RegisterDTO request) {
    if(userRepository.findByUsername(request.username()).isPresent()) {
      throw new IllegalArgumentException("Username already exists");
    }
    if(userRepository.findByEmail(request.email()).isPresent()) {
      throw new IllegalArgumentException("Email already exists");
    }

    var user = User.builder()
        .username(request.username())
        .email(request.email())
        .password(passwordEncoder.encode(request.password()))
        .build();

    User savedUser = userRepository.save(user);

    return new UserResponseDTO(savedUser.getId(), savedUser.getUsername(), savedUser.getEmail());
  }

  public AuthResponseDTO login(LoginDTO request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.username(),
            request.password()
        )
    );

    var user = userRepository.findByUsername(request.username())
        .orElseThrow(() -> new IllegalArgumentException("Invalid username or password"));

    var jwtToken = jwtService.generateToken(user);

    return new AuthResponseDTO(jwtToken);
  }
}
