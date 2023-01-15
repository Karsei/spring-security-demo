package kr.pe.karsei.springsecuritydemo;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@Order(0) // 여러 개가 있을 경우 @Order 를 사용해야 함. 0번째
public class SecurityMultipleConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // admin URL 에 해당하는 경로는 모두 HTTP 인증 방식을 받도록 함
                .antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .httpBasic()
        ;
    }
}

@Configuration
@Order(1) // 1번째
class SecurityMultipleConfig2 extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // admin URL 을 제외하고 어떠한 경로에도 허용을 하도록 함
                .authorizeRequests()
                .anyRequest().permitAll()
                .and()
                .formLogin()
        ;
    }
}