package kr.pe.karsei.springsecuritydemo.security.config;

import kr.pe.karsei.springsecuritydemo.domain.Roles;
import kr.pe.karsei.springsecuritydemo.security.provider.CustomAuthenticationProvider;
import kr.pe.karsei.springsecuritydemo.security.service.CustomUserDetailService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private final AuthenticationDetailsSource authenticationDetailsSource;
    private final CustomUserDetailService userDetailsService;
    private final AuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final AuthenticationFailureHandler customAuthenticationFailureHandler;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*
        String password = passwordEncoder().encode("1111");

        auth.inMemoryAuthentication().withUser("user").password(password).roles(Roles.USER.name());
        auth.inMemoryAuthentication().withUser("manager").password(password).roles(Roles.MANAGER.name(), Roles.USER.name());
        auth.inMemoryAuthentication().withUser("admin").password(password).roles(Roles.ADMIN.name(), Roles.USER.name(), Roles.MANAGER.name());
         */
        auth.authenticationProvider(authenticationProvider());
        //auth.userDetailsService(userDetailsService);
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/users", "/login*").permitAll()
                .antMatchers("/mypage").hasRole(Roles.USER.name())
                .antMatchers("/messages").hasRole(Roles.MANAGER.name())
                .antMatchers("/config").hasRole(Roles.ADMIN.name())
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll()
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
