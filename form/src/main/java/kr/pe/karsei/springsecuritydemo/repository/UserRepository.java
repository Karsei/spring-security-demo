package kr.pe.karsei.springsecuritydemo.repository;

import kr.pe.karsei.springsecuritydemo.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
}
