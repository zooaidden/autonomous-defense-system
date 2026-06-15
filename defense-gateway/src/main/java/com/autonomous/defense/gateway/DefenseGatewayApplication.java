package com.autonomous.defense.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class DefenseGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(DefenseGatewayApplication.class, args);
    }
}

