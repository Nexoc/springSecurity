package at.davl.springSecurity.config;

import at.davl.springSecurity.services.AuthenticationSuccessHandler;
import at.davl.springSecurity.services.MyUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Autowired
    private MyUserDetailService userDetailService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable) // TODO CSRF by default close all post requests
                .authorizeHttpRequests(registry -> {
                    registry.requestMatchers("/index", "/register/**").permitAll();
                    registry.requestMatchers("/admin/**").hasRole("ADMIN");
                    registry.requestMatchers("/user/**").hasRole("USER");
                    registry.anyRequest().authenticated();
                })
                // we give permission to get form Login for all
                //.formLogin(formLogin -> formLogin.permitAll())
                .formLogin(httpSecurityFormLoginConfigurer -> {
                    httpSecurityFormLoginConfigurer
                            .loginPage("/login")
                            // if authentication is successful will set right default page
                            .successHandler(new AuthenticationSuccessHandler())
                            .permitAll();
                })
                .build();
    }

/*
    @Bean
    public UserDetailsService userDetailsService() {
        // https://bcrypt-generator.com/
        UserDetails normalUser = User.builder()
                .username("nex")
                // we create extra func to encode or decode pass
                .password("$2a$12$b5epm5/ngYeEVbi2jGfRj.V0.HinUUfdYhN.2fuoARnVkMNe3aPjS") // 0880
                .roles("USER")
                .build();

        UserDetails adminUser = User.builder()
                .username("admin")
                // we create extra func to encode or decode pass
                .password("$2a$12$nydm9fOisjFU1ditweZhcuMQSLdqdY9UnPuqXI8Kz3zwCBVRbj1uq") // 1234
                .roles("ADMIN", "USER")
                .build();

        return new InMemoryUserDetailsManager(normalUser, adminUser);
    }
 */

    @Bean
    public UserDetailsService userDetailsService() {
        return userDetailService;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        // data access object
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        /*
        + Argon2        ->          BCrypt      ->       Scrypt ->               PBKDF2
        + High                      Moderate             Good                    Poor
        + high secure systems       For                  Balance of secure       For low budget Apps
                                    Web Apps              and performance
         */
        return new BCryptPasswordEncoder();
    }
}
