package com.security.springJwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

	@GetMapping("/demo")
	public ResponseEntity<String> Demo(){
		return ResponseEntity.ok("Hello");
	}
	
	@GetMapping("/admin_only")
	public ResponseEntity<String> admin_only(){
		return ResponseEntity.ok("Admin only url");
	}
}
