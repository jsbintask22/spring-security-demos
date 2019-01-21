package cn.jsbintask.securityrestful.controller;

import cn.jsbintask.securityrestful.common.ResultVO;
import cn.jsbintask.securityrestful.domain.Role;
import cn.jsbintask.securityrestful.domain.User;
import cn.jsbintask.securityrestful.repository.RoleRepository;
import cn.jsbintask.securityrestful.repository.UserRepository;
import cn.jsbintask.securityrestful.util.JwtUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.Collections;
import java.util.List;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/21 10:34
 */
@RestController
@RequestMapping
public class UserController {
    @Resource
    private UserRepository userRepository;
    @Resource
    private RoleRepository roleRepository;

    @GetMapping("/token")
    public ResultVO login(String username, String password) {
        User user = userRepository.findByUsername(username);

        if (user == null || !user.getPassword().equals(password)) {
            ResultVO<Object> result = new ResultVO<>();
            result.setCode(10);
            result.setMsg("用户名或密码错误");
            return result;
        }

        ResultVO<Object> success = new ResultVO<>();
        //用户名密码正确，生成token给客户端
        success.setCode(0);
        List<Role> roles = Collections.singletonList(roleRepository.findById(user.getId()).get());
        success.setData(JwtUtil.generateToken(username, roles));

        return success;
    }
}
