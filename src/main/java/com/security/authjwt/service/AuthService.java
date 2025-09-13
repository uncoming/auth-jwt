package com.security.authjwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import com.security.authjwt.dto.LoginRequest;

import com.security.authjwt.repository.IUserRepository;
import com.security.authjwt.entity.User;
import java.util.List;


import java.security.Key;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthService {
	
	private static final String SECRET = "12345678901234567890123456789012";
	
	private final IUserRepository userRepository;
	
	private Key getSigningKey() {
		return Keys.hmacShaKeyFor(SECRET.getBytes());
	}

	public User registerUser(User user) {
		if (userRepository.getByUsername(user.getUsername()).isPresent()) {
			throw new IllegalArgumentException("El usuario ya existe");
		}
		return userRepository.save(user);
	}

	public List<User> getAllUsers() {
		return userRepository.findAll();
	}
	
	public String generateToken(LoginRequest login) {
		
		var userOpt = userRepository.getByUsername(login.getUsername());

		if(!userOpt.isPresent() || !userOpt.get().getPassword().equals(login.getPassword())) {
			return "Credenciales invalidas.";
		}

		return Jwts.builder()
				.setSubject(login.getUsername())
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis()+3600000)) // 1 hora
				.signWith(getSigningKey(), SignatureAlgorithm.HS256)
				.compact();
	}
	
	public String validateTokenAndGetUsername(String token) {
		Claims claims = Jwts.parserBuilder()
				.setSigningKey(getSigningKey())
				.build()
				.parseClaimsJws(token)
				.getBody();
		return claims.getSubject();
	}

}
