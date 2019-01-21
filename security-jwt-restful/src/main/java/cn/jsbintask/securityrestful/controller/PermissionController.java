package cn.jsbintask.securityrestful.controller;

import cn.jsbintask.securityrestful.common.ResultVO;
import cn.jsbintask.securityrestful.domain.AuthUser;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/21 14:02
 */
@RestController
@RequestMapping
public class PermissionController {

    @GetMapping("/normal")
    public ResultVO loginTest(@AuthenticationPrincipal AuthUser authUser) {
        ResultVO<String> resultVO = new ResultVO<>();
        resultVO.setCode(0);

        resultVO.setData("你成功访问了 '/normal' 这个api，这代表你已经登录，你是： " + authUser);
        return resultVO;
    }

    @GetMapping("/role")
    @PreAuthorize("hasRole('user')")
    public ResultVO loginTest() {
        ResultVO<String> resultVO = new ResultVO<>();
        resultVO.setCode(0);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        resultVO.setData("你成功访问了/role这个api，这代表你已经登陆了，并且你有 'user' 这个身份，你的信息：" + authentication);
        return resultVO;
    }
}
