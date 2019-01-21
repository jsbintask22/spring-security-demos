package cn.jsbintask.securityrestful.config;

import cn.jsbintask.securityrestful.domain.AuthUser;
import cn.jsbintask.securityrestful.util.JwtUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/21 11:52
 */
@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("token");

        //获取token，并且解析token，如果解析成功，则放入 SecurityContext
        if (token != null) {
            try {
                AuthUser authUser = JwtUtil.parseToken(token);
                //todo: 如果此处不放心解析出来的 authuser，可以再从数据库查一次，验证用户身份：

                //解析成功
                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    //我们依然使用原来filter中的token对象
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(authUser,
                            null,
                            authUser.getAuthorities());

                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }
            } catch (Exception e) {
                logger.info("解析失败，可能是伪造的或者该token已经失效了（我们设置失效5分钟）。");
            }
        }

        filterChain.doFilter(request, response);
    }
}
