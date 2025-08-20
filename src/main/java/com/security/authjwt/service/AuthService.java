package com.security.authjwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import com.security.authjwt.dto.LoginRequest;
import com.security.authjwt.entity.User;
import com.security.authjwt.repository.IUserRepository;

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
	
	public String generateToken(LoginRequest login) {
		User user = userRepository.getByUsername(login.getUsername());
		if(user == null || !login.getPassword().equals(user.getPassword())){
			return "Credenciales invalidas.";
		}
		return Jwts.builder()
				.setSubject(login.getUsername())
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis()+60000))
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
