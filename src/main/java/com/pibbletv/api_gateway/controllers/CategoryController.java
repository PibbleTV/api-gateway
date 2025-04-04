package com.pibbletv.api_gateway.controllers;

import com.pibbletv.api_gateway.dtos.CategoryDTO;
import com.pibbletv.api_gateway.dtos.UserDTO;
import jdk.jfr.Category;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import reactor.core.publisher.Flux;

@RestController
@RequestMapping("/api-category")
public class CategoryController {

    private final WebClient webClient;

    // Inject WebClient.Builder for creating the WebClient instance
    public CategoryController(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl("http://category-service").build();  // Set the base URL for category service
    }

    @GetMapping("/getAll")
    public Flux<CategoryDTO> getAll(@AuthenticationPrincipal Jwt jwt) {
        // Optionally use the JWT to add some user context if needed
        String userId = jwt.getSubject();  // Get the user ID from the JWT token, if required

        // URL for the category service
        String categoryServiceUrl = "/category/getAll?userId=" + userId;

        // Use WebClient to make a non-blocking GET request to the category service
        return this.webClient.get()
                .uri(categoryServiceUrl)  // Pass the constructed URL
                .retrieve()  // Initiate the request
                .bodyToFlux(CategoryDTO.class);  // Convert the response body into a Flux of CategoryDTO
    }
}