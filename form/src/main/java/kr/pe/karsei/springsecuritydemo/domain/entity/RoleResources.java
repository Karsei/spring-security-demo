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
@Table(name = "role_resources")
@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RoleResources {
    @Id
    @Column(name = "resource_id")
    private Long resourceId;
    @Column(name = "role_id")
    private Long roleId;
}
