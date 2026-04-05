package com.repositorio.mvp.controller;

import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.repositorio.mvp.DTO.auth.AuthenticationDTO;
import com.repositorio.mvp.DTO.auth.LoginResponseDTO;
import com.repositorio.mvp.DTO.register.RegisterDTO;
import com.repositorio.mvp.repository.UserRepository;
import com.repositorio.mvp.repository.InvalidatedTokenRepository;
import com.repositorio.mvp.service.LoginAttemptService;
import com.repositorio.mvp.service.TokenService;
import com.repositorio.mvp.service.TotpService;
import com.repositorio.mvp.model.InvalidatedToken;
import com.repositorio.mvp.model.User;
import com.repositorio.mvp.model.UserRole;

import org.springframework.web.bind.annotation.RequestBody;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository repository;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private InvalidatedTokenRepository invalidatedTokenRepository;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private TotpService totpService;

    //POST /api/auth/login
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody @Valid AuthenticationDTO data,
                                HttpServletRequest request) {

        String ip = request.getRemoteAddr();
        int attempts = loginAttemptService.getAttempts(ip);

        int delay = Math.min(attempts, 6);
        System.out.println("Ip está bloqueado");
        //Verificação de Bloqueio de IP
        if (loginAttemptService.isBlocked(ip)) {
            return ResponseEntity.status(429).body("IP temporarily blocked due to too many failed attempts");
        }
        
        if (delay > 0) {
            System.out.println("Aplicando delay de " + delay + " segundos para o IP");
            try {
                Thread.sleep(delay * 1000);//TODO modificar futuramente 
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        //MFA
        try {
            var usernamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password());
            var auth = this.authenticationManager.authenticate(usernamePassword);

            User user = (User) auth.getPrincipal();
            if (user.isMfaEnabled()) {
                if (data.totpCode() == null || data.totpCode().isBlank()) {
                    return ResponseEntity.status(403).body("Código 2FA é obrigatório.");
                }
                try {
                    int code = Integer.parseInt(data.totpCode());

                    if (!totpService.verifyCode(user.getMfaSecret(), code)) {
                        loginAttemptService.loginFailed(ip);
                        return ResponseEntity.status(401).body("Código 2FA inválido.");
                    }
                } catch (NumberFormatException e) {
                    loginAttemptService.loginFailed(ip);
                    return ResponseEntity.status(400).body("Formato de código 2FA inválido.");
                }
            }

            loginAttemptService.loginSucceeded(ip);
            var token = tokenService.generateToken(user.getId());

            return ResponseEntity.ok(new LoginResponseDTO(token));

        } catch (Exception e) {
            loginAttemptService.loginFailed(ip);
            return ResponseEntity.status(500).body("An unexpected error occurred.");
        }
    }
 
    //POST /api/auth/logout
    @PostMapping("/logout")
    public ResponseEntity logout(HttpServletRequest request){

        String authHeader = request.getHeader("Authorization");

        if(authHeader == null || !authHeader.startsWith("Bearer "))
            return ResponseEntity.badRequest().build();

        String token = authHeader.substring(7);

        Instant expiration = tokenService.getExpiration(token);

        System.out.println("Invalidando token LOGOUT");
        invalidatedTokenRepository.save(
            new InvalidatedToken(token, expiration)
        );

        return ResponseEntity.ok().build();
    }   

    //GET /api/auth/setup-2fa
    @GetMapping("/setup-2fa")
    public ResponseEntity<String> setup2fa(HttpServletRequest request) {

        String authHeader = request.getHeader("Authorization");
        String token = authHeader.replace("Bearer ", "");
        var userIdOpt = tokenService.validateToken(token);
        
        if (userIdOpt.isEmpty()) return ResponseEntity.status(401).build();
        
        User user = repository.findById(userIdOpt.get()).orElseThrow();

        String secret = totpService.generateSecret();
        user.setMfaSecret(secret);
        user.setMfaEnabled(true);
        repository.save(user);
        
        System.out.println("Secret gerado MFA");

        String qrCodeUrl = totpService.getQrCodeUrl(user.getEmail(), secret);
        
        return ResponseEntity.ok(qrCodeUrl);
    }
}
