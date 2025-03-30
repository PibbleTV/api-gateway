package com.pibbletv.api_gateway.controllers;

import com.pibbletv.api_gateway.dtos.UserDTO;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@RestController
@RequestMapping("/api-user")
public class UserController {

    private final RestTemplate restTemplate;

    public UserController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @PostMapping(value = "/saveUser")
    public ResponseEntity<Void> saveUser(@AuthenticationPrincipal Jwt jwt) {

        String userId = jwt.getSubject();
        String username = jwt.getClaimAsString("preferred_username");


        Map<String, Object> data = Map.of(
                "userId", userId,
                "username", username
        );


        String userServiceUrl = "http://user-service/user/saveUser";

        restTemplate.postForEntity(userServiceUrl, data, Void.class);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/getUserByToken")
    public ResponseEntity<UserDTO> getUserByToken(@AuthenticationPrincipal Jwt jwt) {

        String userId = jwt.getSubject();

        String userServiceUrl = "http://user-service/user/getUser?userId=" + userId;

        UserDTO user = restTemplate.getForObject(userServiceUrl, UserDTO.class);

        return ResponseEntity.ok(user);
    }
}