package com.nqvinh.keycloak.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/home")
public class HomeController {

    @GetMapping(value = "/public")
    public ResponseEntity<Object> home() {
        return new ResponseEntity<>("PAGE_PUBLIC", HttpStatus.OK);
    }

    @GetMapping(value = "/admin")
    public ResponseEntity<Object> homeAdmin() {
        return new ResponseEntity<>("PAGE_ADMIN", HttpStatus.OK);
    }
}
