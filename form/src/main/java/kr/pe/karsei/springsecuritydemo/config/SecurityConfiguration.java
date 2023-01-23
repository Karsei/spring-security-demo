package kr.pe.karsei.springsecuritydemo.config;

import kr.pe.karsei.springsecuritydemo.domain.Roles;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        String password = passwordEncoder().encode("1111");

        auth.inMemoryAuthentication().withUser("user").password(password).roles(Roles.USER.name());
        auth.inMemoryAuthentication().withUser("manager").password(password).roles(Roles.MANAGER.name(), Roles.USER.name());
        auth.inMemoryAuthentication().withUser("admin").password(password).roles(Roles.ADMIN.name(), Roles.USER.name(), Roles.MANAGER.name());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/users").permitAll()
                .antMatchers("/mypage").hasRole(Roles.USER.name())
                .antMatchers("/messages").hasRole(Roles.MANAGER.name())
                .antMatchers("/config").hasRole(Roles.ADMIN.name())
                .anyRequest().authenticated()
                .and()
                .formLogin()
        ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                // permitAll 과 비교했을 때 보안 필터를 거치지 않음
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
        ;
    }
}
