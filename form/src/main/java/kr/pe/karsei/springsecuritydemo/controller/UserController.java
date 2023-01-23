package kr.pe.karsei.springsecuritydemo.controller;

import kr.pe.karsei.springsecuritydemo.domain.Account;
import kr.pe.karsei.springsecuritydemo.domain.AccountDto;
import kr.pe.karsei.springsecuritydemo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("mypage")
    public String myPage() {
        return "user/mypage";
    }

    @GetMapping("users")
    public String createUser() {
        return "user/login/register";
    }

    @PostMapping("users")
    public String createUser(AccountDto accountDto) {
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        account.setPassword(passwordEncoder.encode(account.getPassword()));

        userService.createUser(account);

        return "redirect:/";
    }
}
