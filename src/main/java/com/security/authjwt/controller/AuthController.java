package com.security.authjwt.controller;

import com.security.authjwt.dto.LoginRequest;
import com.security.authjwt.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class AuthController {
	
	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
	private final AuthService authService;
	
	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest){
		logger.info("Login attempt by user: {} from IP: {}", request.getUsername(), httpRequest.getRemoteAddr());
		String token = authService.generateToken(request.getUsername());
		return ResponseEntity.ok(token);
	}
	
	@GetMapping("/welcome")
	public ResponseEntity<String> welcome(
			@RequestHeader(value = "Authorization", required = false) String authHeader,
			HttpServletRequest request){
		
		String ip = request.getRemoteAddr();
		String userAgent = request.getHeader("User-Agent");
		String traceId = java.util.UUID.randomUUID().toString();
		
		if(authHeader == null || authHeader.isBlank()) {
			logger.warn("Unauthorized access attempt from ID: {}, UA: {}, trace-id: {}", ip, userAgent, traceId);
			return ResponseEntity.status(401).body("No autorizado: Falta el token");
		}
		
		try {
			String username = authService.validateTokenAndGetUsername(authHeader.replace("Bearer ", ""));
			logger.info("Successful token validation for user: {}, IP: {}, UA: {}, trace-id: {}", username, ip, userAgent, traceId);
			return ResponseEntity.ok("Bienvenido " + username);
		}catch(Exception e){
			logger.info("Invalid token attempt from IP: {}, UA: {}, trace-id: {}", ip, userAgent, traceId);
			return ResponseEntity.status(401).body("Token invalido o expirado");
		}
	}

}
