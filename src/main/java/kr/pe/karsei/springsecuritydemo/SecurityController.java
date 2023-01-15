package kr.pe.karsei.springsecuritydemo;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {
    @GetMapping("/")
    public String index(HttpSession session) {
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

        // 아래의 두 객체는 서로 같다
        Authentication authentication1 = context.getAuthentication();
        Authentication authentication2 = SecurityContextHolder.getContext().getAuthentication();


        return "home";
    }

    @GetMapping("thread")
    public String thread() {
        // SecurityContext 는 ThreadLocal 에 저장되어 아무 곳에서나 참조 가능.
        // 기본 전략은 MODE_THREADLOCAL
        new Thread(new Runnable() {
            @Override
            public void run() {
                // 메인 스레드에서 인증 정보를 얻었다고 해서 자식 스레드에서는 인증 정보를 얻지 못한다. 따라서 이 결과는 null 이 나온다.
                // 전략을 MODE_INHERITABLETHREADLOCAL 이면 획득할 수 있다.
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            }
        }).start();

        return "thread";
    }

    @GetMapping("loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("user")
    public String user() {
        return "user";
    }

    @GetMapping("admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("admin/**")
    public String admin() {
        return "admin";
    }

    @GetMapping("denied")
    public String denied() {
        return "Access is denied";
    }

    @GetMapping("login")
    public String login() {
        return "login";
    }
}
