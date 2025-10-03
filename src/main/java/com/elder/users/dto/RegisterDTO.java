package com.elder.users.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterDTO(@NotBlank(message = "Username cannot be blank") String username,
                          @NotBlank(message = "Email cannot be blank")
                          @Email(message = "Invalid email format")
                          String email,
                          @NotBlank(message = "Password cannot be blank") @Size(min = 6,
                              message = "Password most have at least 6 characters")
                          String password) {
}
