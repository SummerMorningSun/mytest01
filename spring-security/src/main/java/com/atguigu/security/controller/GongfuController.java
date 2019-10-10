package com.atguigu.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class GongfuController {
	@GetMapping("/level1/1")
	public String leve11Page(){
		return "level1/1";
	}
	@GetMapping("/level1/2")
	public String leve12Page(){
		return "level1/2";
	}
	@GetMapping("/level1/3")
	public String leve13Page(){
		return "level1/3";
	}
	
	@GetMapping("/level2/{path}")
	public String leve2Page(@PathVariable("path")String path){
		return "level2/"+path;
	}
	
	@GetMapping("/level3/{path}")
	public String leve3Page(@PathVariable("path")String path){
		return "level3/"+path;
	}

}
