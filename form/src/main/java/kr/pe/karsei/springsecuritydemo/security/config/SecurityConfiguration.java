package kr.pe.karsei.springsecuritydemo.security.config;

import kr.pe.karsei.springsecuritydemo.security.factory.UrlResourceMapFactoryBean;
import kr.pe.karsei.springsecuritydemo.security.handler.CustomAccessDeniedHandler;
import kr.pe.karsei.springsecuritydemo.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import kr.pe.karsei.springsecuritydemo.security.provider.CustomAuthenticationProvider;
import kr.pe.karsei.springsecuritydemo.security.service.CustomUserDetailService;
import kr.pe.karsei.springsecuritydemo.security.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.sql.CallableStatement;
import java.util.Arrays;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private final AuthenticationDetailsSource authenticationDetailsSource;
    private final CustomUserDetailService userDetailsService;
    private final AuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final AuthenticationFailureHandler customAuthenticationFailureHandler;
    private final SecurityResourceService securityResourceService;

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

    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                // customFilterSecurityInterceptor 를 설정했기 때문에 이 부분을 처리하는 MetadataSource 를 읽는다 하더라도 건너뛰게 된다.
                // FilterChainProxy 를 살펴보면 FilterSecurityInterceptor 2개가 생긴 것을 볼 수 있고, ExpressionBasedFilterInvocationSecurityMetadataSource 를 사용하는
                // Interceptor 보다 앞으로 위치하도록 했기 때문에 아래 코드는 건너뛰게 된다.
//                        .antMatchers("/", "/users", "/login*").permitAll()
//                        .antMatchers("/mypage").hasRole(Roles.USER.name())
//                        .antMatchers("/messages").hasRole(Roles.MANAGER.name())
//                        .antMatchers("/config").hasRole(Roles.ADMIN.name())
                        .anyRequest().authenticated()
                .and()
                .exceptionHandling()
                        .accessDeniedHandler(accessDeniedHandler())

                .and()
                .addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)
                .formLogin()
                        .loginPage("/login")
                        .loginProcessingUrl("/login_proc")
                        .defaultSuccessUrl("/")
                        .authenticationDetailsSource(authenticationDetailsSource)
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

    @Bean
    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
        FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
        interceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        interceptor.setAccessDecisionManager(affirmativeBased());
        interceptor.setAuthenticationManager(authenticationManagerBean());
        return interceptor;
    }

    private AccessDecisionManager affirmativeBased() {
        return new AffirmativeBased(getAccessDecisionVoters());
    }

    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
        return List.of(new RoleVoter());
    }

    @Bean
    public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
//        return new UrlFilterInvocationSecurityMetadataSource();
        return new UrlFilterInvocationSecurityMetadataSource(urlResourceMapFactoryBean().getObject());
    }

    private UrlResourceMapFactoryBean urlResourceMapFactoryBean() {
        UrlResourceMapFactoryBean urlResourceMapFactoryBean = new UrlResourceMapFactoryBean();
        urlResourceMapFactoryBean.setSecurityResourceService(securityResourceService);
        return urlResourceMapFactoryBean;
    }
}
