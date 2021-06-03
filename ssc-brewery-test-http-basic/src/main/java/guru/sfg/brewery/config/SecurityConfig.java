package guru.sfg.brewery.config;

import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
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
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
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
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("{bcrypt}$2a$10$YFuwOOBYN5PUNJdzY/DR8.AJgpNGxH0HBatVpvPoFD6N60ayv5b6y")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("{sha256}3d6377dcb6ce3760ef5a948876636f107da546af51e5e621b4e79bbac30940323e641d69d7ac6822")
                .roles("USER")
                .and()
                .withUser("scott")
                .password("{ldap}{SSHA}ZEFhTsf+kP1oNpH6OndMDkJdre++BRgvLJZS0g==")
                .roles("CUSTOMER");
    }
}
