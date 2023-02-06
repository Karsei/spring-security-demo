package kr.pe.karsei.springsecuritydemo.config;

import kr.pe.karsei.springsecuritydemo.repository.ResourcesRepository;
import kr.pe.karsei.springsecuritydemo.security.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfiguration {
    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository) {
        SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository);
        return securityResourceService;
    }
}
