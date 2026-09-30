package com.amazonaws.serverless.proxy.spring.filterauthapp;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A plain Spring Boot servlet application whose only protection on /admin/* is a servlet Filter registered with a
 * path-scoped url-pattern. This is the configuration the reported authorization bypass affects - hand-rolled filter
 * authorization, as opposed to Spring Security.
 */
@SpringBootApplication
@RestController
public class FilterAuthApplication {
    public static final String SECRET_BODY = "TOP_SECRET";
    public static final String PUBLIC_BODY = "PUBLIC_OK";

    @GetMapping("/admin/secret")
    public String adminSecret() {
        return SECRET_BODY;
    }

    @GetMapping("/public/info")
    public String publicInfo() {
        return PUBLIC_BODY;
    }

    @Bean
    public FilterRegistrationBean<AdminAuthorizationFilter> adminAuthorizationFilter() {
        FilterRegistrationBean<AdminAuthorizationFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AdminAuthorizationFilter());
        registration.addUrlPatterns("/admin/*");
        registration.setName("adminAuthorizationFilter");
        return registration;
    }
}
