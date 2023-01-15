package kr.pe.karsei.springsecuritydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
//    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("{noop}1111") // 특정 패스워드 알고리즘 유형을 prefix 형태로 적어야 나중에 패스워드 일치 여부 확인 시 검증 시 도움이 됨. noop 은 평문으로 하라는 뜻
                .roles("USER");
        auth.inMemoryAuthentication()
                .withUser("sys")
                .password("{noop}1111")
                .roles("SYS", "USER");
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER"); // 나중에 계층적으로 권한을 설정해줄 수 있긴 하지만 우선은 이렇게 직접 여러 개를 명시함으로써 모든 권한을 줄 수 있다.
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated()
//        ;
        http
                .authorizeRequests()
                        .antMatchers("/login").permitAll() // 이거 안하면 인증을 받아야 하기 때문에 허용을 해줌
                        .antMatchers("/user").hasRole("USER")
                        .antMatchers("/admin/pay").hasRole("ADMIN")
                        .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                        .anyRequest().authenticated()
        ;
        //http
        //        .antMatcher("/shop/**") // 사용자의 요청이 여기에 설정된 자원 경로에 접근할 때만 아래의 기능이 작동한다. 다른 경로면 작동하지 않는다. 만약 생략하면 모든 경로를 대상으로 한다.
        //        .authorizeRequests()
        //        .antMatchers("/shop/login", "/shop/users/**").permitAll() // 동일한 정보가 있거나 포함되면 뒤에 있는 권한 정보에 따라 모든 인가 승인을 진행한다.
        //        .antMatchers("/shop/mypage").hasRole("USER") // 해당 경로 요청은 USER 라는 역할을 가지고 있어야 접근이 가능하다.
        //        .antMatchers("/shop/admin/pay").access("hasRole('ADMIN')")
        //        .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
        //        .anyRequest().authenticated()
        // 주의할 점은 설정 시 구체적인 경로가 먼저 오고, 그것보다 큰 범위의 경로가 뒤에 오도록 해야 한다.
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
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response); // 사용자가 가고자 했던 요청 정보
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl); // 인증에 성공한 다음 바로 세션에 저장되어 있던 이전의 정보를 꺼내와서 이동하도록 함
                        //response.sendRedirect("/");
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
        http
                // 로그인 시 SessionManagementFilter -> session.expireNow() 로 이전 사용자 세션 만료(최대 세션 허용 개수가 초과되었을 경우)
                // 이전 사용자가 요청 시 ConcurrentSessionFilter -> 위의 메서드로 세션만료 체크 후 true 면 logout 후 오류 페이지 응답
                .sessionManagement() // 세션 관리 기능이 동작함

                .sessionFixation() // 세션 고정 보호
                .changeSessionId() // 기본값. none, migrateSession, newSession

                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 세션 정책
                /*
                ALWAYS - 항상 세션 생성
                IF_REQUIRED - 필요 시 생성 (기본값)
                NEVER - 생성하지 않지만 이미 존재하면 사용
                STATELESS - 생성하지 않고 존재해도 사용하지 않음
                 */

                .invalidSessionUrl("/invalid") // 세션이 유효하지 않을 때 이동할 페이지 // 체이닝 조심할 것
                .maximumSessions(1) // 최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(true) // 동시 로그인 차단함, false : 기존 세션 만료(default)
                .expiredUrl("/expired") // 세션이 만료된 경우 이동할 페이지
        ;
        http
                .exceptionHandling() // 예외 처리 기능이 작동함
                .authenticationEntryPoint(new AuthenticationEntryPoint() { // 인증 실패 시 처리
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() { // 인가 실패 시 처리
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                })
        ;

        // SecurityContext 객체 저장 방식
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL); // 기본값
        // SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }
}
