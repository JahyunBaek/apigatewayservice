package com.example.apigatewayservice.fiters;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Component
@Slf4j
@RefreshScope
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    @Value("${jwt.secret.key}")
    private String salt;

    @Value("${jwt.access-token-validity-in-seconds}")
    private long a_exp;

    private Key secretKey;

    public AuthorizationHeaderFilter() {

        super(AuthorizationHeaderFilter.Config.class);
    }

    @Data
    public static class Config{
        private String baseMessage;
        private boolean preLogger;
        private boolean postLogger;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange,"no Authorization header.", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String Jwt = authorizationHeader.replace("Bearer ","");

            if(!isJwtValid(Jwt)){
                return onError(exchange,"token is not valid.", HttpStatus.UNAUTHORIZED);
            }

            //custom post filter
            return chain.filter(exchange);
        });
    }

    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;
//        secretKey = Keys.hmacShaKeyFor(salt.getBytes(StandardCharsets.UTF_8));
//        String subject = null;
//        try{
//            subject = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(jwt).getBody().getSubject();
//        }catch (Exception e){
//            returnValue = false;
//        }
//
//        if(subject == null || subject.isEmpty()){
//            returnValue = false;
//        }

        return returnValue;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(err);
        return  response.setComplete();
    }
}
