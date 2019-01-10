---
title: springsecurity系列教程-基础配置详解
date: 2019-01-10 10:15
updated: 2019-01-10 14:15
tag: 
  - java
  - springsecurity
  - springboot
sourceId: springsecurity-basicconfig
---
*[上一章](https://jsbintask.cn/2019/01/08/springsecurity-configsourcecode/#more)我们从源码角度探究了springboot对于帮我们初始化的springsecurity默认配置，这章我们来学习下springsecurity中的基础配置*
# 修改基础配置
* 上一章我们已经知道，springsecurity中所有配置基本都来源于一个默认的WebSecurityConfigurerAdapter，那我们首先写一个类继承它，放弃springboot帮我们做的默认配置，
叫SecurityConfig，为了看到更多的配置，我们加上一个注解（其实springboot已经帮我们加上），@EnableWebSecurity(debug = true)，修改debug位true，
然后打开我们的配置文件application.yml，修改spring的log信息为debug，如下：
```yaml
server:
  port: 8080

spring:
  freemarker:
    enabled: true
    cache: false
    template-loader-path: classpath:/templates/
    suffix: .html

  security:
    user:
      name: user
      password: admin
      roles: user, admin
logging:
  level:
    org.springframework.*: debug
```

# 配置详解
* 打开SecurityConfig，首先明确我们的目的：修改原来的登陆页面，登陆成功后，跳转到我们的hello页面，所以首先添加登陆页面login.html，并且添加视图解析（和第一章一样添加controller同样效果）：
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>login page</title>
</head>
<body>
This is login page from jsbintask
<form action="/login" method="post">
    username: <input name="username" /><br/>
    password: <input name="password" /><br/>
    <button type="submit">submit</button>
</form>
</body>
</html>
```
这里请记住这个表单提交的地址/login，写一个类WebMvcConfig实现WebMvcConfigurer（2.0以前需要继承WebMvcConfigurerAdapter），添加如下配置:
```java
@Configuration
@EnableWebMvc
public class WebMvcConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/index").setViewName("login");
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
    }
}
```
* 接着继续回来SecurityConfig,首先覆盖下原方法**configure(HttpSecurity http)**，我们看下原来实现是什么：
```java
protected void configure(HttpSecurity http) throws Exception {
		logger.debug("Using default configure(HttpSecurity). If subclassed this will potentially override subclass configure(HttpSecurity).");

		http
			.authorizeRequests()
				.anyRequest().authenticated()
				.and()
			.formLogin().and()
			.httpBasic();
	}
```
可以看出，默认配置就是所有页面全部被拦截，开启登陆表单验证以及http basic验证，我们继续查看**formLogin()**方法:
```java
public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
		return getOrApply(new FormLoginConfigurer<>());
	}
```
熟悉的apply方法，上一章已经介绍，这是添加拦截器，FormLoginConfigurer如下：
```java
public FormLoginConfigurer() {
		super(new UsernamePasswordAuthenticationFilter(), null);
		usernameParameter("username");
		passwordParameter("password");
	}
```
加了一个UsernamePasswordAuthenticationFilter拦截器。接下来，我们修改configure配置如下，值得注意的是，因为现在我们的页面是自己的定义，但是所有页面
都是需要权限的，所以我们必须放行登陆（error页面在BaseErrorController中定义），错误页面：
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
            .loginPage("/index")
            // 和login.html中表单提交的一直必须一样，这样才能让springsecurity帮你处理请求
            .loginProcessingUrl("/login")
            .and()
            .authorizeRequests()
            .antMatchers("/index", "/login", "/error").permitAll()
            .anyRequest()
            .authenticated();
}
```
接着启动项目，查看控制台，发现多个springsecurity的日志：
o.s.s.web.DefaultSecurityFilterChain     : Creating filter chain: any request, [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@60d40ff4, org.springframework.security.web.context.SecurityContextPersistenceFilter@58867cd5, org.springframework.security.web.header.HeaderWriterFilter@2c05ff9d, org.springframework.security.web.csrf.CsrfFilter@44ed0a8f, org.springframework.security.web.authentication.logout.LogoutFilter@70211df5, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@4c5228e7, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@5a8ab2, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@71926a36, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@2e5b7fba, org.springframework.security.web.session.SessionManagementFilter@2e1ddc90, org.springframework.security.web.access.ExceptionTranslationFilter@2687725a, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@c29fe36]
看得出这就是我们上一章说的过滤器链了。并且UsernamePasswordAuthenticationFilter也在其中
接下来打开浏览器，直接访问主界面， [http://localhost:8080/hello](http://localhost:8080/hello)，自动跳转到了我们自定义的登陆页面：
![security](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo8.png)
然后点击提交，发现403错误了，纳尼？ 赶紧检查控制台，发现走了一个CrsfFilter，这个filter需要一个参数，防止xss攻击的，但是我们不需要，所以我们禁掉，如下：
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
            .loginPage("/index")
            .loginProcessingUrl("/login")
            .and()
            .authorizeRequests()
            .antMatchers("/index", "/login", "/error", "/favicon.ico").permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .csrf()
            .disable();
}
```
这回正常了，我们输入错误的用户名，密码，果然，回到了原来的登陆页面，如下：
![security](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo9.png)
并且后面带了一个error的参数，所以如果我们的login页面再做下处理，就能回显用户名密码错误了。然后我们继续输入我们一开始已经配置用户名密码，继续，这回出现了404，
![security](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo10.png)
看地址我们知道它是登陆成功后帮我回到了 http://localhost:8080作为了默认页面，所以我们要加上登陆成功后的页面如下，也就是hello
```java
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
```
继续登陆，果然，成功后帮我们重定向到了hello页面：
![security](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo11.png)
# 自定义数据查询
经过上面的配置，我们一开始的目的达到了，自定义登陆页面，并且登陆成功后跳转到主界面，但是现在还有个问题是，我们的用户名密码是配置配置文件中的，这样肯定不行，
因为我们一般都是使用数据库的。接下来就是我们自定义数据源了。
## 内存中的数据源
上一篇博客我们已经通过源码分析了springboot在启动的时候帮我们初始化了一个在内存中的UserDetailService，如下：
![security](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo12.png)
那我们现在先来覆盖掉这个，回到先前的SecurityConfig，并且继承方法**configure(AuthenticationManagerBuilder auth)**，
在自定义UserDetailsService的时候，发现它要求返回一个UserDetails，所以我们需要继承这个类来返回自己的实体类User，因为我们这里使用内存中的实现，可以直接用它提供的工具方法：
```java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(new InMemoryUserDetailsManager(
            User.builder().username("jsbintask1").password("{noop}123456").authorities("jsbintask1").build(),
            User.builder().username("jsbintask2").password("{noop}123456").authorities("jsbintask2").build()
    ));
}
```
值得注意的是，如果我们以这种方式定义密码的时候，要在密码前面加上{noop}这个前缀或者配置一个密码加密器的bean，否则验证会出错。另外还有一点就是一定要添加roles或者authorities，
否则springsecurity不予通过。现在我们重新登陆，并且使用一开始配置文件中的用户名密码，发现此时已经不行了。 再用我们的新用户名密码，通过！
![security](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo13.png)
到这里，我们的自定义内存中的数据源就定义好了，接下来我们换成数据库中的形式。

## db形式的数据源
* 因为要使用数据库，那我们就选用spring-data jpa去操作数据库，首先引入依赖:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
</dependency>
```