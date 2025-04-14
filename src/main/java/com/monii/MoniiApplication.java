package com.monii;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class MoniiApplication {

	public static void main(String[] args) {
		SpringApplication.run(MoniiApplication.class, args);
	}

}
