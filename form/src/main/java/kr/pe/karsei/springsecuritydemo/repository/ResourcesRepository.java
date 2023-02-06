package kr.pe.karsei.springsecuritydemo.repository;

import kr.pe.karsei.springsecuritydemo.domain.entity.Resources;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResourcesRepository extends JpaRepository<Resources, Long> {
    List<Resources> findAllResourcesBy();
}
