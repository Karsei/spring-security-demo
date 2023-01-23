package kr.pe.karsei.springsecuritydemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
	@GetMapping
	public String home() {
		return "home";
	}

	@GetMapping(value = "login")
	public String login()  {
		return "login";
	}
}