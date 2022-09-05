package com.fang.supportportal.filter;

import com.fang.supportportal.utility.JWTTokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

import static com.fang.supportportal.constant.SecurityConstant.OPTIONS_HTTP_METHOD;
import static com.fang.supportportal.constant.SecurityConstant.TOKEN_PREFIX;

@Component
@AllArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JWTTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getMethod().equalsIgnoreCase(OPTIONS_HTTP_METHOD)) {
            response.setStatus(HttpStatus.OK.value());
            return;
        }

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null || authorizationHeader.startsWith(TOKEN_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.substring(TOKEN_PREFIX.length()); // remove "Bearer" words, leave only token
        String username = jwtTokenProvider.getSubject(token);
        if (jwtTokenProvider.isTokenValid(username, token) && SecurityContextHolder.getContext().getAuthentication() == null) {
            List<GrantedAuthority> authorities = jwtTokenProvider.getAuthorities(token);
            Authentication authentication = jwtTokenProvider.getAuthentication(username, authorities, request);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return;
        }
        SecurityContextHolder.clearContext();

        filterChain.doFilter(request, response);
    }
}
