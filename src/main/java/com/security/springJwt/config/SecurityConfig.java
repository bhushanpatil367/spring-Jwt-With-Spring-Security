package com.security.springJwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.security.springJwt.filter.JwtAuthenticationFilter;
import com.security.springJwt.service.UserServiceImpl;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final UserServiceImpl userServiceImpl;
	
	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	
	
	
	public SecurityConfig(UserServiceImpl userServiceImpl, JwtAuthenticationFilter jwtAuthenticationFilter) {
		super();
		this.userServiceImpl = userServiceImpl;
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
	}



	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		return http
				.csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(
						req -> req.requestMatchers("/login/**", "register/**").permitAll()
						.requestMatchers("/admin_only/**").hasAuthority("ADMIN")
						.anyRequest()
						.authenticated()
						).userDetailsService(userServiceImpl)
				.sessionManagement(session -> session
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}
}
