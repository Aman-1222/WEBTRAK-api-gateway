package com.example.api_gateway.filter;

import com.example.api_gateway.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    private static final List<String> PUBLIC_PATHS = List.of(
            "/user-service/users/login"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();
        HttpMethod method = exchange.getRequest().getMethod();

        // 1️⃣ Public endpoints
        if (isPublic(path)) {
            return chain.filter(exchange);
        }

        // 2️⃣ Authorization header
        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange);
        }

        String token = authHeader.substring(7);

        // 3️⃣ Validate token
        if (!jwtUtil.isValid(token)) {
            return unauthorized(exchange);
        }

        // 4️⃣ Role-based restriction: POST /users → ADMIN or HR only
        if (path.equals("/user-service/users") && method == HttpMethod.POST) {

            List<String> roles = jwtUtil.getRoles(token);

            if (roles == null ||
                    (!roles.contains("ADMIN") && !roles.contains("HR"))) {

                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
        }

        // 4️⃣ Role-based restriction: PROJECT SERVICE → ADMIN or HR only
        if (path.startsWith("/project-service")) {

            List<String> roles = jwtUtil.getRoles(token);

            if (roles == null ||
                    (!roles.contains("ADMIN") && !roles.contains("HR"))) {

                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
        }

        if (path.startsWith("/leave-service/leaves")) {

            List<String> roles = jwtUtil.getRoles(token);

            // EMPLOYEE APIs
            if (
                    (path.equals("/leave-service/leaves") && method == HttpMethod.POST) ||
                            (path.equals("/leave-service/leaves/my") && method == HttpMethod.GET)
            ) {
                if (!roles.contains("EMPLOYEE")) {
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                }
            }

            // ADMIN / HR APIs
            if (
                    (path.equals("/leave-service/leaves") && method == HttpMethod.GET) ||
                            path.contains("/approve") ||
                            path.contains("/reject")
            ) {
                if (!roles.contains("ADMIN") && !roles.contains("HR")) {
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                }
            }
        }

        // 5️⃣ Forward user info to downstream services
        ServerWebExchange modifiedExchange = exchange.mutate()
                .request(r -> r
                        .header("X-USER-EMAIL", jwtUtil.getEmail(token))
                        .header("X-USER-ROLES",
                                String.join(",", jwtUtil.getRoles(token)))
                )
                .build();

        return chain.filter(modifiedExchange);
    }

    private boolean isPublic(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
