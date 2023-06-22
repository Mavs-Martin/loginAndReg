package com.martin.loginandreg.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.martin.loginandreg.services.UserService;

import jakarta.servlet.http.HttpSession;

@Controller
public class HomeController {

	private final UserService userServ;
	public HomeController(UserService userServ) {
		this.userServ = userServ;
	}
	
	@GetMapping("/")
	public String home(HttpSession session, Model model) {
		if(session.getAttribute("user_id") == null) {
			return "redirect:/users/login/register";
		}
		model.addAttribute("loggedInUser", userServ.getUser((Long)session.getAttribute("user_id")));
		return "main/dashboard.jsp";
	}

}
