package kr.pe.karsei.springsecuritydemo.domain;

import lombok.Getter;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Getter
public class Account {
    @Id
    @GeneratedValue
    private Long id;
    private String username;
    private String password;
    private String email;
    private int age;
    private String role;

    public void setPassword(String password) {
        this.password = password;
    }
}
