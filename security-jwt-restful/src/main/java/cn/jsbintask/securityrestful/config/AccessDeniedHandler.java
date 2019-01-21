package cn.jsbintask.securityrestful.config;

import cn.jsbintask.securityrestful.common.ResultVO;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/21 11:44
 */
@Component
public class AccessDeniedHandler implements org.springframework.security.web.access.AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 返回我们的自定义json
        ObjectMapper objectMapper = new ObjectMapper();
        ResultVO<Object> result = new ResultVO<>();
        //50，标识有token，但是该用户没有权限
        result.setCode(50);
        result.setMsg("请求无效，没有有效token");
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }
}
