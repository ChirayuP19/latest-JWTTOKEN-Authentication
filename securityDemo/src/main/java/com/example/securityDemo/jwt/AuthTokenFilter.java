package com.example.securityDemo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger log= LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.debug("AuthTokenFilter called for URI {}",request.getRequestURI());
        try {
            String jwt=parseJwt(request);
            if(jwt!=null && jwtUtils.validateJwtToke(jwt)){
                String username=jwtUtils.getUsernameFromJwt(jwt);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                authenticationToken.setDetails
                        (new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                log.debug("Roles from JWT: {}",userDetails.getAuthorities());
            }
        }catch (Exception e){
            log.error("Cannot set User authentication: {}",e.getMessage());
        }
        filterChain.doFilter(request,response);
    }

    private String parseJwt(HttpServletRequest request) {
        String jwt=jwtUtils.getJwtFromHeader(request);
        log.debug("AuthTokenFilter.java {}",jwt);
        return jwt;
    }
}
