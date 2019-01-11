package cn.jsbintask.basicsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author jsbintask@foxmail.com
 * @date 2019/1/4 15:36
 */
@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .loginPage("/index")
                .loginProcessingUrl("/login")
                .successForwardUrl("/hello")
                .and()
                .authorizeRequests()
                .antMatchers("/index", "/login", "/error", "/favicon.ico").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .csrf()
                .disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /* for memorysource */
        /*auth.userDetailsService(new InMemoryUserDetailsManager(
                User.builder().username("jsbintask1").password("{noop}123456").authorities("jsbintask1").build(),
                User.builder().username("jsbintask2").password("{noop}123456").authorities("jsbintask2").build()
        ));*/

        /* for dbsource */
        /*auth.userDetailsService(userDetailsService);*/
        super.configure(auth);
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        System.out.println(bCryptPasswordEncoder.encode("123456"));
    }

}
