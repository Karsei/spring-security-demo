package kr.pe.karsei.springsecuritydemo.service;

import kr.pe.karsei.springsecuritydemo.domain.Account;

public interface UserService {
    void createUser(Account account);
}
