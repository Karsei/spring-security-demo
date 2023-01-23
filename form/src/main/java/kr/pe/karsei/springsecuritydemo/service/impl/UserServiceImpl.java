package kr.pe.karsei.springsecuritydemo.service.impl;

import kr.pe.karsei.springsecuritydemo.domain.Account;
import kr.pe.karsei.springsecuritydemo.repository.UserRepository;
import kr.pe.karsei.springsecuritydemo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service("userService")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
