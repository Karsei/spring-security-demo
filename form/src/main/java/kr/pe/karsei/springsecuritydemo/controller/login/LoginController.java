package kr.pe.karsei.springsecuritydemo.controller.login;

import kr.pe.karsei.springsecuritydemo.domain.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {
    @GetMapping("login")
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception,
                        Model model) {
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
        return "user/login/login";
    }

    @GetMapping("logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return "user/login/logout";
    }

    @GetMapping("denied")
    public String accessDenied(@RequestParam(value = "exception", required = false) String exception,
                               Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Account principal = (Account) auth.getPrincipal();

        model.addAttribute("username", principal.getUsername());
        model.addAttribute("exception", exception);

        return "user/login/denied";
    }
}
