package cn.jsbintask.securityrestful.config;

import cn.jsbintask.securityrestful.common.ResultVO;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationConfig;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/21 11:39
 */
@Component
public class TokenExceptionHandler implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // 直接返回 json错误
        ResultVO<Object> result = new ResultVO<>();
        //20，标识没有token
        result.setCode(20);
        result.setMsg("请求无效，没有有效token");

        ObjectMapper objectMapper = new ObjectMapper();

        response.getWriter().write(objectMapper.writeValueAsString(result));
    }
}
