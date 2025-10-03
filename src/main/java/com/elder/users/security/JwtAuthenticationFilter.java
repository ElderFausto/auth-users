package com.elder.users.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtService jwtService;
  private final UserDetailsService userDetailsService;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain
  ) throws ServletException, IOException {

    final String authHeader = request.getHeader("Authorization");

    // 1. Verifica se o cabeçalho Authorization existe e começa com "Bearer "
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }

    // 2. Extrai o token do cabeçalho
    final String jwt = authHeader.substring(7); // "Bearer ".length()
    final String username = jwtService.extractUsername(jwt);

    // 3. Valida o token e o usuário
    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

      if (jwtService.isTokenValid(jwt, userDetails)) {
        // Se o token for válido, cria um objeto de autenticação
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            userDetails,
            null, // Não usamos credenciais (senha) aqui
            userDetails.getAuthorities()
        );
        authToken.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request)
        );

        // 4. Atualiza o SecurityContextHolder com a nova autenticação
        SecurityContextHolder.getContext().setAuthentication(authToken);
      }
    }
    // 5. Continua a cadeia de filtros
    filterChain.doFilter(request, response);
  }
}