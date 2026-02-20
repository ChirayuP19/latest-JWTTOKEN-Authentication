package com.example.securityDemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)throws  Exception{
        DefaultSecurityFilterChain build = http
                .csrf(crsf->crsf.disable())
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(x -> x.anyRequest().authenticated()).httpBasic(Customizer.withDefaults()).build();
        return build;
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.withUsername("user2")
                .password(passwordEncoder().encode("password2")).roles("USER").build();

        UserDetails admin = User.withUsername("admin2")
                .password(passwordEncoder().encode("admin2")).roles("ADMIN").build();

        JdbcUserDetailsManager userDetailsManager=new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
        return userDetailsManager;

    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    
}
