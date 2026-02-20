package com.example.securityDemo.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);

    @Value("{JwtExpirationMs}")
    private long JwtExpirationMs;
    @Value("{jwtSecret}")
    private String jwtSecret;

    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken=request.getHeader("Authorization");
        log.debug("Authorization Header {} ",bearerToken);
        if(bearerToken !=null && bearerToken.startsWith("Bearer "))
            return bearerToken.substring(7);
        return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails){
        String username=userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date().getTime()+JwtExpirationMs)))
                .signWith(key())
                .compact();
    }

    public String getUsernameFromJwt(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public Key key(){
        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecret)
        );
    }

    public boolean validateJwtToke(String authToken){
        try {
                log.info("Validate");
                Jwts.parser()
                        .verifyWith((SecretKey) key())
                        .build()
                        .parseSignedClaims(authToken);
                return true;
        }catch (MalformedJwtException e){
            log.error("Invalid JWT Token: {}",e.getMessage());
        }catch (ExpiredJwtException e){
            log.error("JWT Token is expired: {}",e.getMessage());
        }catch (UnsupportedJwtException e){
            log.error("JWT Token is unsupported: {}",e.getMessage());
        }catch (IllegalArgumentException e){
            log.error("JWT claims string is empty: {}",e.getMessage());
        }
        return false;
    }

}
