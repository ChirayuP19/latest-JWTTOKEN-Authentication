package com.example.securityDemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

    @GetMapping("/health_check")
    public String healthCheck(){
        return "ok";
    }

    @GetMapping("/use")
    public String userEndPoints(){
        return "hello. User! ";
    }


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String AdminEndPoints(){
        return "hello. Admin! ";
    }
}
