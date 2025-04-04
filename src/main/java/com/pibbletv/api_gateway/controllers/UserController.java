package com.pibbletv.api_gateway.controllers;

import com.pibbletv.api_gateway.dtos.UserDTO;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api-user")
public class UserController {

    private final WebClient webClient;

    public UserController(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl("http://user-service").build();
    }

    @PostMapping(value = "/saveUser")
    public Mono<Void> saveUser(@AuthenticationPrincipal Jwt jwt) {

        String userId = jwt.getSubject();
        String username = jwt.getClaimAsString("preferred_username");

        Map<String, Object> data = Map.of(
                "userId", userId,
                "username", username
        );

        String userServiceUrl = "/user/saveUser";

        return this.webClient.post()
                .uri(userServiceUrl)
                .bodyValue(data)
                .retrieve()
                .bodyToMono(Void.class);
    }

    @GetMapping("/getUserByToken")
    public Mono<UserDTO> getUserByToken(@AuthenticationPrincipal Jwt jwt) {

        String userId = jwt.getSubject();

        String userServiceUrl = "/user/getUser?userId=" + userId;

        return this.webClient.get()
                .uri(userServiceUrl)
                .retrieve()
                .bodyToMono(UserDTO.class);
    }

    @GetMapping("/getUserById")
    public Mono<UserDTO> getUserById(@RequestParam String id, @AuthenticationPrincipal Jwt jwt) {
        String requesterId = jwt.getSubject();

        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        List<String> roles = realmAccess != null ? (List<String>) realmAccess.get("roles") : Collections.emptyList();


        if (!requesterId.equals(id) && !roles.contains("admin")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
        }

        String userServiceUrl = "/user/getUserById?userId=" + id;

        return this.webClient.get()
                .uri(userServiceUrl)
                .retrieve()
                .bodyToMono(UserDTO.class);
    }
}