package guru.sfg.brewery.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
                http
                    .authorizeRequests(authorize -> {
                                       authorize.antMatchers("/", "/webjars/**", "/login","/resources/**").permitAll()
                                                .antMatchers("/beers/find", "/beers*").permitAll()
                                                .antMatchers(HttpMethod.GET,"/api/v1/beer/**").permitAll()
                                                .antMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                })
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic();
    }

    @Bean
    PasswordEncoder passwordEncoder () {
        return new BCryptPasswordEncoder();
    }

    //Fluent API
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("{SSHA}htr/NqFI1lKxuCUWx9FkY+Vbw4Zv5gC+M/dxDw==")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("$2a$10$lzP9inHl82HbM7a1MakdZu/jq0YagoU8nGUoWjH.6ADYOti0cLShW")
                .roles("USER")
                .and()
                .withUser("scott")
                .password("{SSHA}htr/NqFI1lKxuCUWx9FkY+Vbw4Zv5gC+M/dxDw==")
                .roles("CUSTOMER");
    }
}
