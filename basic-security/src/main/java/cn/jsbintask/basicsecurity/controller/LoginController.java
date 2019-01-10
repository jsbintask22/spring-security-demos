package cn.jsbintask.basicsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/10 9:38
 */
@Controller
@RequestMapping
public class LoginController {

    @PostMapping("/login")
    public String login(String username, String password) {
        System.out.println(username + ", " + password);

        return "hello";
    }
}
