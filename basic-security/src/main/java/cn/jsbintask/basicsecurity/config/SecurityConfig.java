package cn.jsbintask.basicsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/4 15:36
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .loginPage("/index")
                .and()
                .authorizeRequests()
                .antMatchers("/index").permitAll()
                .anyRequest()
                .authenticated();
    }
}
