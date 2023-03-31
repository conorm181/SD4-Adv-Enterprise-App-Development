package com.sd4.L11.config;


import jakarta.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;



@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /** Spring Security will evaluate the rules
        in the order they are defined, and the first matching
        rule will be applied.**/

       http.csrf().disable()
               .authorizeHttpRequests()
               .requestMatchers("/", "/content").permitAll()
               .requestMatchers(HttpMethod.GET, "/reports/**")
               .hasRole("MANAGER")
               .requestMatchers(HttpMethod.GET, "/documents/**")
               .hasAnyRole("MANAGER", "USER")
               .requestMatchers(HttpMethod.GET, "/content/**")
               .hasAnyRole("MANAGER", "USER")
               .requestMatchers(request -> request.getMethod().equals("GET") && request.getServletPath().contains("ment"))
               .hasAnyRole("EMPLOYEE")
               .anyRequest()
               .authenticated()
               .and()
               .formLogin()
         //      .failureUrl("/failure")
               .defaultSuccessUrl("/content");
        return http.build();
    }


    @Bean
    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user =  User.withUsername("dave")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();
        UserDetails manager =  User.withUsername("emma")
                .password(passwordEncoder.encode("password"))
                .roles("MANAGER")
                .build();
        UserDetails employee =  User.withUsername("grace")
                .password(passwordEncoder.encode("password"))
                .roles("EMPLOYEE")
                .build();
        UserDetails nobody =  User.withUsername("tom")
                .password(passwordEncoder.encode("password"))
                .roles("NOBODY")
                .build();
        return new InMemoryUserDetailsManager(user, manager, employee, nobody);
    }


    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
}




//////////////////////////////////
//Simple Config
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.csrf().disable()
//                .authorizeHttpRequests()
//                .requestMatchers("/").permitAll()
//                .requestMatchers(HttpMethod.GET, "/reports/**")
//                .hasRole("MANAGER")
//                .requestMatchers(HttpMethod.GET, "/documents/**")
//                .hasAnyRole("USER")
//                .anyRequest()
//                .authenticated()
//                .and()
//                .formLogin()
//                .defaultSuccessUrl("/content");
//        return http.build();
//    }
//
//    @Bean
//    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
//        UserDetails user =  User.withUsername("dave")
//                .password(passwordEncoder.encode("password"))
//                .roles("USER")
//                .build();
//        UserDetails manager =  User.withUsername("emma")
//                .password(passwordEncoder.encode("password"))
//                .roles("MANAGER","USER")
//                .build();
//        return new InMemoryUserDetailsManager(user, manager);
//    }


