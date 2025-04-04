package com.pibbletv.api_gateway.controllers;

import com.pibbletv.api_gateway.dtos.CategoryDTO;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;

@RestController
@RequestMapping("/api-category")
public class CategoryController {

    private final WebClient webClient;


    public CategoryController(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl("http://category-service").build();
    }

    @GetMapping("/getAll")
    public Flux<CategoryDTO> getAll() {

        String categoryServiceUrl = "/category/getAll";


        return this.webClient.get()
                .uri(categoryServiceUrl)
                .retrieve()
                .bodyToFlux(CategoryDTO.class);
    }
}