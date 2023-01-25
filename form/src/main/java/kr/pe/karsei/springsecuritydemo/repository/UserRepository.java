package kr.pe.karsei.springsecuritydemo.repository;

import kr.pe.karsei.springsecuritydemo.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByUsername(String username);
}
