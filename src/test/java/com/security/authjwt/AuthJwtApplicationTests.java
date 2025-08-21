package com.security.authjwt;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

//@SpringBootTest
class AuthJwtApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void testGenerateTokenAndValidate() {
		// Mock del repositorio
		com.security.authjwt.entity.User mockUser = new com.security.authjwt.entity.User();
		mockUser.setUsername("testuser");
		mockUser.setPassword("testpass");

		com.security.authjwt.repository.IUserRepository userRepository = org.mockito.Mockito.mock(com.security.authjwt.repository.IUserRepository.class);
		org.mockito.Mockito.when(userRepository.getByUsername("testuser")).thenReturn(mockUser);

		com.security.authjwt.service.AuthService service = new com.security.authjwt.service.AuthService(userRepository);

		com.security.authjwt.dto.LoginRequest login = new com.security.authjwt.dto.LoginRequest();
		login.setUsername("testuser");
		login.setPassword("testpass");

		String token = service.generateToken(login);
		org.junit.jupiter.api.Assertions.assertNotNull(token);
		org.junit.jupiter.api.Assertions.assertFalse(token.contains("Credenciales invalidas"));

		String username = service.validateTokenAndGetUsername(token);
		org.junit.jupiter.api.Assertions.assertEquals("testuser", username);

		// Prueba credenciales inválidas
		login.setPassword("wrong");
		String invalid = service.generateToken(login);
		org.junit.jupiter.api.Assertions.assertEquals("Credenciales invalidas.", invalid);
	}

}
