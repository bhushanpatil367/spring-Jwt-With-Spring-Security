package com.security.springJwt.service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.security.springJwt.model.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	private final String SECREAT_KEY = "e202d4dea73c18250eeca7850d9e0c84566162770ce2af18d2ee648a5299aa12";

	//6
	public boolean isValid(String token, UserDetails user) {
		String username  = extractUsername(token);
		return (username.equals(user.getUsername())) && !isTokenExpired(token);
	}
	
	//7
	private boolean isTokenExpired(String token) {
		
		return extractExpiration(token).before(new Date());
	}

	//8
	private Date extractExpiration(String token) {
		
		return extractClaim(token, Claims::getExpiration);
	}

	//finish jwt code time for filters 
	
	//5
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	//4
	public <T> T extractClaim(String token, Function<Claims, T> resolver) {
		Claims claims = extractAllClaims(token);
		return resolver.apply(claims);
	}
	
	
	//3
	private Claims extractAllClaims(String token) {
		return Jwts
				.parser()
				.verifyWith(getSigninKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}
	
	//1
	public String generateToken(User user) {
		
		String token = Jwts
				.builder()
				.subject(user.getUsername())
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis()+ 24*60*60*1000))
				.signWith(getSigninKey())
				.compact();
		
		return token;
	}

	//2
	private SecretKey getSigninKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECREAT_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
