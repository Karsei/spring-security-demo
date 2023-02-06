package kr.pe.karsei.springsecuritydemo.domain.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "role")
@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Role {
    @Id
    private Long id;

    @Column(name = "role_desc")
    private String roleDesc;

    @Column(name = "role_name")
    private String roleName;
}
