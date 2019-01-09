package cn.jsbintask.basicsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/4 15:38
 */
@Controller
@RequestMapping
public class HelloController {

    @RequestMapping("/hello")
    public String hello(ModelAndView mv) {
        return "hello";
    }
}
