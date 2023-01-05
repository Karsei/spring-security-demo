package kr.pe.karsei.springsecuritydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
        ;
        http
                .formLogin() // Form 로그인 인증 기능이 작동함
                //.loginPage("/loginPage") // 로그인 페이지 경로 지정 (인증을 받지 않아도 접근이 가능해야 한다)
                .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                .failureUrl("/login.html?error=true") // 로그인 실패 후 이동 페이지
                .usernameParameter("username") // 아이디 파라미터명 설정
                .passwordParameter("password") // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login") // 로그인 Form Action Url
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication - " + authentication.getName());
                        response.sendRedirect("/");
                    }
                }) // 로그인 성공 후 핸들러
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception - " + exception.getMessage());
                        response.sendRedirect("/login.html?error=true");
                    }
                }) // 로그인 실패 후 핸들러
                .permitAll()
        ;
        http
                // 로그아웃 처리
                .logout()
                // 로그아웃 처리 URL
                .logoutUrl("/logout")
                // 로그아웃 성공 후 이동 페이지
                .logoutSuccessUrl("/login")
                // 로그아웃 후 쿠키 삭제
                .deleteCookies("JSESSIONID", "remember-me")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("logout");
                        response.sendRedirect("/login");
                    }
                })
        ;
        http
                .rememberMe() // remember
                .rememberMeParameter("remember") // 기본파라미터명은 remember-me
                .tokenValiditySeconds(3600) // 유지시간으로서 1시간. 기본값은 14일
                .alwaysRemember(true) // remember-me 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService) // 시스템에 있는 사용자를 처리하는 과정에 필요한 것
        ;
    }
}
