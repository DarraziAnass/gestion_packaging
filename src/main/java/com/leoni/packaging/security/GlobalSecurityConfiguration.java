package com.leoni.packaging.security;

import com.leoni.packaging.dto.PostGroupDto;
import com.leoni.packaging.model.AppUser;
import com.leoni.packaging.model.Group;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.util.Collection;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class GlobalSecurityConfiguration {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authenticationProvider(authenticationProvider())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/resources/**","/webjars/**","/static/**", "/css/**", "/images/**").permitAll()
                        .requestMatchers(HttpMethod.GET,"/change-password").permitAll()
                        .requestMatchers("/admin/**").hasAuthority("ADMIN")
                        .requestMatchers("/user/**").hasAnyAuthority("USER")
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(authenticationSuccessHandler())
                        .permitAll()
                )
                .build();
    }

    @Bean
    AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        return authenticationProvider;
    }

    @Bean
    AuthenticationSuccessHandler authenticationSuccessHandler(){
        RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
        SecurityContextLogoutHandler contextLogoutHandler = new SecurityContextLogoutHandler();
        return (request, response, authentication) -> {
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            if (authorities.contains(new SimpleGrantedAuthority("ADMIN"))) {
                redirectStrategy.sendRedirect(request, response, "/admin/statistics");
            } else if (authorities.contains(new SimpleGrantedAuthority("USER"))) {
                AppUser user = (AppUser) authentication.getPrincipal();
                Group group = user.getGroup();
                String userRedirectPath="/user/scan/";
                if(group !=null){
                    if(!PostGroupDto.validTime(group)){
                        contextLogoutHandler.logout(request, response, null);
                        throw new IllegalStateException("user out of service");
                    }
                }else{
                    contextLogoutHandler.logout(request, response, null);
                    throw new IllegalStateException("user not affected to any group");
                }
                redirectStrategy.sendRedirect(request, response, userRedirectPath);
            } else {
                contextLogoutHandler.logout(request, response, null);
                throw new IllegalStateException("Unexpected user role");
            }
        };
    }

}
