package com.security.authjwt.controller;

import com.security.authjwt.dto.LoginRequest;
import com.security.authjwt.service.AuthService;
import com.security.authjwt.entity.User;
import java.util.List;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

@RestController
@RequiredArgsConstructor
@Tag(name = "Auth", description = "Operaciones de autenticación y bienvenida protegida por JWT")
public class AuthController {
	
	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
	private final AuthService authService;

	@Operation(
		summary = "Registrar nuevo usuario",
		description = "Crea un nuevo usuario en la base de datos.",
		requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
			required = true,
			content = @Content(
				schema = @Schema(implementation = User.class),
				examples = @ExampleObject(value = "{\"username\":\"nuevo\",\"password\":\"clave\"}")
			)
		),
		responses = {
			@ApiResponse(responseCode = "201", description = "Usuario creado", content = @Content(schema = @Schema(implementation = User.class))),
			@ApiResponse(responseCode = "400", description = "Datos inválidos", content = @Content(schema = @Schema(type = "string")))
		}
	)
	@PostMapping("/register")
	public ResponseEntity<?> register(@RequestBody User user) {
		try {
			User created = authService.registerUser(user);
			return ResponseEntity.status(201).body(created);
		} catch (Exception e) {
			logger.error("Error al registrar usuario: {}", e.getMessage());
			return ResponseEntity.badRequest().body("No se pudo registrar el usuario: " + e.getMessage());
		}
	}

	@Operation(
		summary = "Obtener todos los usuarios",
		description = "Devuelve la lista de todos los usuarios registrados.",
		responses = {
			@ApiResponse(responseCode = "200", description = "Lista de usuarios", content = @Content(schema = @Schema(implementation = User.class)))
		}
	)
	@GetMapping("/users")
	public ResponseEntity<List<User>> getAllUsers() {
		List<User> users = authService.getAllUsers();
		return ResponseEntity.ok(users);
	}
	
	@Operation(
		summary = "Login de usuario",
		description = "Autentica un usuario y retorna un JWT si las credenciales son válidas.",
		requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
			required = true,
			content = @Content(
				schema = @Schema(implementation = LoginRequest.class),
				examples = @ExampleObject(value = "{\"username\":\"usuario\",\"password\":\"clave\"}")
			)
		),
		responses = {
			@ApiResponse(responseCode = "200", description = "Token JWT generado correctamente", content = @Content(schema = @Schema(type = "string"))),
			@ApiResponse(responseCode = "401", description = "Credenciales inválidas", content = @Content(schema = @Schema(type = "string")))
		}
	)
	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest){
		logger.info("Login attempt by user: {} from IP: {}", request.getUsername(), httpRequest.getRemoteAddr());
		String token = authService.generateToken(request);
		return ResponseEntity.ok(token);
	}
	
	@Operation(
		summary = "Endpoint protegido de bienvenida",
		description = "Devuelve un mensaje de bienvenida si el JWT es válido. Requiere header Authorization: Bearer {token}",
		parameters = {
			@Parameter(name = "Authorization", description = "Token JWT en formato Bearer", required = false, example = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6...")
		},
		responses = {
			@ApiResponse(responseCode = "200", description = "Token válido, acceso permitido", content = @Content(schema = @Schema(type = "string"))),
			@ApiResponse(responseCode = "401", description = "Token inválido o ausente", content = @Content(schema = @Schema(type = "string")))
		}
	)
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
