package com.authserver.app.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    private static final String USER = "USER";
    private static final String ADMIN = "ADMIN";


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors().disable()
                .csrf().disable()
                .formLogin();

        http.oauth2ResourceServer(
                        oauth2ResourceServerCustomizer ->
                                oauth2ResourceServerCustomizer.jwt().jwkSetUri("http://172.26.0.1:9090/oauth2.jwks")
                )
                .authorizeRequests()
                .anyRequest().permitAll();

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var userDetailsService = new InMemoryUserDetailsManager();

        var user = User
                .withUsername("user")
                .password(bCryptPasswordEncoder().encode("user"))
                .roles(USER)
                .build();

        var admin = User
                .withUsername("admin")
                .password(bCryptPasswordEncoder().encode("admin"))
                .roles(ADMIN)
                .build();

        userDetailsService.createUser(user);
        userDetailsService.createUser(admin);
        return userDetailsService;
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
