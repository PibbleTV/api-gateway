import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteLocatorConfig {

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("user-service", r -> r.path("/user/**")
                        .and().method("POST")
                        .and().readBody(User.class, s -> true)
                        .filters(f -> f.filters(requestFilter, authFilter))
                        .uri("lb://user-service")) // Using Eureka service discovery

                .route("user-service", r -> r.path("/user/**")
                        .and().method("GET")
                        .filters(f -> f.filters(authFilter))
                        .uri("lb://user-service"))

                .route("category-service", r -> r.path("/category/**")
                        .and().method("POST")
                        .and().readBody(Category.class, s -> true)
                        .filters(f -> f.filters(requestFilter, authFilter))
                        .uri("lb://category-service"))

                .route("category-service", r -> r.path("/category/**")
                        .and().method("GET")
                        .filters(f -> f.filters(authFilter))
                        .uri("lb://category-service"))

                .route("follows-service", r -> r.path("/following/**")
                        .filters(f -> f.filters(authFilter))
                        .uri("lb://follows-service"))

                .build();
    }
}
