---
title: springsecurity系列教程-初始化配置源码解析
date: 2019-01-08 14:15
updated: 2019-01-08 14:15
tag: 
  - java
  - springsecurity
  - springboot
sourceId: springsecurity-configsourcecode
---

# Springsecurity从helloworld到源码解析（二）：springsecurity配置加载解析
*上一篇博客我们介绍了hellowrold入门，并且成功的看到了springsecurity的拦截效果，接下来我们就来看看springsecurity是如何做到的。*

# 启动配置详解
我们知道（不知道的就当知道吧，哈哈），springboot启动时会帮我自动配置好很多的默认配置项，并且加载配置类都会写在spring.factories文件中，所以我们这里开始，看看springsecurity做了
那些配置，打开idea，ctrl+shift+n * 2，查找spring.factories文件：如下：
[spring.factories](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo3.png)
随后在该配置文件中，查找security，如下：
[security](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo4.png)
我们可以看到，一共初始化了9个security相关的类，这里我们不关注oauth2（以后再说）和reactive（springboot2以后新特性），还有
**SecurityAutoConfiguration， SecurityRequestMatcherProviderAutoConfiguration， SecurityFilterAutoConfiguration**这三个类，首先我们看下
### SecurityAutoConfiguration：
```java
@Configuration
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
@EnableConfigurationProperties(SecurityProperties.class)
@Import({ SpringBootWebSecurityConfiguration.class, WebSecurityEnablerConfiguration.class,
		SecurityDataConfiguration.class })
public class SecurityAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean(AuthenticationEventPublisher.class)
	public DefaultAuthenticationEventPublisher authenticationEventPublisher(
			ApplicationEventPublisher publisher) {
		return new DefaultAuthenticationEventPublisher(publisher);
	}

}
```
* 1.可以看出，这个类初始化了DefaultAuthenticationEventPublisher，看名字就知道，一个事件发布器，其内部实现就是spring的ApplicationEventPublisher，
用于springsecurity各种权限时间的交互，如登陆失败，会发布一个事件，然后通知其它组件做出相应的响应。

* 2.导入了一个配置类，SecurityProperties，如下：
```java
private String name = "user";

private String password = UUID.randomUUID().toString();

private List<String> roles = new ArrayList<>();

private boolean passwordGenerated = true;
```
现在我们知道，我们上一篇博客中yml文件中配置的用户名密码就是这这里的配置，如果不进行配置，默认生成一个uuid的密码，从控制台可以看到该密码。

* 3.另外导入了三个配置项
**SpringBootWebSecurityConfiguration.class, WebSecurityEnablerConfiguration.class, SecurityDataConfiguration.class**
其中data相关的因为此处我们没有导入spring-data相关的引用，不生效。
然后我们继续观察 WebSecurityEnablerConfiguration.class，看名字我们知道这是web环境下的初始化的配置，如下：
```java
@Configuration
@ConditionalOnBean(WebSecurityConfigurerAdapter.class)
@ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
public class WebSecurityEnablerConfiguration {

}
```
主要作用帮我们加入了 **@EnableWebSecurity**注解，该注解的作用为开启springsecurity httpsecurity的自定义配置，即我们可以自己定义web环境的url配置（后面的主要关注点）。
接下来就是**@SpringBootWebSecurityConfiguration**，如下：
```java
@Configuration
@ConditionalOnClass(WebSecurityConfigurerAdapter.class)
@ConditionalOnMissingBean(WebSecurityConfigurerAdapter.class)
@ConditionalOnWebApplication(type = Type.SERVLET)
public class SpringBootWebSecurityConfiguration {

	@Configuration
	@Order(SecurityProperties.BASIC_AUTH_ORDER)
	static class DefaultConfigurerAdapter extends WebSecurityConfigurerAdapter {

	}

}
```
关键点来了，这个配置项检查了servlet环境下spring容器中是否有WebSecurityConfiguraerAdapter这个bean，如果没有，就帮我们默认初始化了一个。所以我们对于springsecurity
的配置就要继承WebSecurityConfigurerAdapter，然后实现自定义的配置。
**以上就是SecurityAutoConfiguration该配置项的作用，接下来我们看下SecurityRequestMatcherProviderAutoConfiguration**

## SecurityRequestMatcherProviderAutoConfiguration
```java
@Configuration
@ConditionalOnClass({ RequestMatcher.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SecurityRequestMatcherProviderAutoConfiguration {

	@Configuration
	@ConditionalOnClass(DispatcherServlet.class)
	@ConditionalOnBean(HandlerMappingIntrospector.class)
	public static class MvcRequestMatcherConfiguration {

		@Bean
		@ConditionalOnClass(DispatcherServlet.class)
		public RequestMatcherProvider requestMatcherProvider(
				HandlerMappingIntrospector introspector) {
			return new MvcRequestMatcherProvider(introspector);
		}

	}

	@Configuration
	@ConditionalOnClass(ResourceConfig.class)
	@ConditionalOnMissingClass("org.springframework.web.servlet.DispatcherServlet")
	@ConditionalOnBean(JerseyApplicationPath.class)
	public static class JerseyRequestMatcherConfiguration {

		@Bean
		public RequestMatcherProvider requestMatcherProvider(
				JerseyApplicationPath applicationPath) {
			return new JerseyRequestMatcherProvider(applicationPath);
		}

	}

}
```
可以看出，主要初始化了一个MvcRequestMatcherProvider，了解过springmvc的同学应该知道，springmvc处理请求映射的主要类就是HandlerMapping，而HandlerMappingIntrospector
类是HandlerMapping的集合工具类，springsecurity此处就是从spring容器中获取了该工具类，然后供自己内部使用(处理我们的自定义映射，后面具体讲解）。
```java
public class MvcRequestMatcherProvider implements RequestMatcherProvider {

	private final HandlerMappingIntrospector introspector;

	public MvcRequestMatcherProvider(HandlerMappingIntrospector introspector) {
		this.introspector = introspector;
	}

	@Override
	public RequestMatcher getRequestMatcher(String pattern) {
		return new MvcRequestMatcher(this.introspector, pattern);
	}

}
```
接下来就是**SecurityFilterAutoConfiguration**了：

## SecurityFilterAutoConfiguration
```java
@Configuration
@ConditionalOnWebApplication(type = Type.SERVLET)
@EnableConfigurationProperties(SecurityProperties.class)
@ConditionalOnClass({ AbstractSecurityWebApplicationInitializer.class,
		SessionCreationPolicy.class })
@AutoConfigureAfter(SecurityAutoConfiguration.class)
public class SecurityFilterAutoConfiguration {

	private static final String DEFAULT_FILTER_NAME = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME;

	@Bean
	@ConditionalOnBean(name = DEFAULT_FILTER_NAME)
	public DelegatingFilterProxyRegistrationBean securityFilterChainRegistration(
			SecurityProperties securityProperties) {
		DelegatingFilterProxyRegistrationBean registration = new DelegatingFilterProxyRegistrationBean(
				DEFAULT_FILTER_NAME);
		registration.setOrder(securityProperties.getFilter().getOrder());
		registration.setDispatcherTypes(getDispatcherTypes(securityProperties));
		return registration;
	}

	private EnumSet<DispatcherType> getDispatcherTypes(
			SecurityProperties securityProperties) {
		if (securityProperties.getFilter().getDispatcherTypes() == null) {
			return null;
		}
		return securityProperties.getFilter().getDispatcherTypes().stream()
				.map((type) -> DispatcherType.valueOf(type.name())).collect(Collectors
						.collectingAndThen(Collectors.toSet(), EnumSet::copyOf));
	}

}
```
首先，我们发现这个类有一个@AutoConfigureAfter(SecurityAutoConfiguration.class)，也就是说这个类要在我们讲的第一个**SecurityAutoConfiguration**才行（why？ 别急），
然后它拿到我们一开始说的SecurityProperties，帮我们做了一个Filter：**但是！这个filter具体是啥，它沒有直接告訴我們，只把它在spring中的bean的名字给出来了，springSecurityFilterChain**，
也就是説存在一个这样名字的springsecurity的filter，然后被spring代理了，管理它的生命周期。但是从名字我们大概可以猜出，不只是一个filter，是一个filter列表，既然这样，那我们直接在项目中搜索，看那个地方有这个名字的bean
最终在该地方找到：
[springSecurityFilterChain](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo5.png)，
发现该类是在WebSecurityConfiguration中初始化的，那**WebSecurityConfiguration**又是在哪来的呢，上面我们说到@EnableWebSecurity的时候，开启WebSecurityAdapter的配置，其实那个时候已经导入了（哈哈，上面我也没注意到），
---

### springSecurityFilterChain
```java
	private WebSecurity webSecurity;

	private Boolean debugEnabled;

	private List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers;

	private ClassLoader beanClassLoader;
	
	@Bean(name = "springSecurityFilterChain")
	public Filter springSecurityFilterChain() throws Exception {
		boolean hasConfigurers = webSecurityConfigurers != null
				&& !webSecurityConfigurers.isEmpty();
		if (!hasConfigurers) {
			WebSecurityConfigurerAdapter adapter = objectObjectPostProcessor
					.postProcess(new WebSecurityConfigurerAdapter() {
					});
			webSecurity.apply(adapter);
		}
		return webSecurity.build();
	}
```
我们注意到这个初始化类有两个主要成员变量，WebSecurity和webSecurityConfigurers，而从这个springSecurityFilterChain方法我们可以看到该filter是通过构造器WebSecurity构造而来，
纳尼？ 既然Websecurity构造了springSecurityFilterChain，那为什么下面还有一个 webSecurityConfigurers，并且是一个WebSecurity的list呢？
别急，我们来看下他们之间的关系。我们注意到还有这样一个方法：
```java
@Autowired(required = false)
public void setFilterChainProxySecurityConfigurer(
        ObjectPostProcessor<Object> objectPostProcessor,
        @Value("#{@autowiredWebSecurityConfigurersIgnoreParents.getWebSecurityConfigurers()}") List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers)
        throws Exception {
    webSecurity = objectPostProcessor
            .postProcess(new WebSecurity(objectPostProcessor));
    if (debugEnabled != null) {
        webSecurity.debug(debugEnabled);
    }

    Collections.sort(webSecurityConfigurers, AnnotationAwareOrderComparator.INSTANCE);

    Integer previousOrder = null;
    Object previousConfig = null;
    for (SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
        Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
        if (previousOrder != null && previousOrder.equals(order)) {
            throw new IllegalStateException(
                    "@Order on WebSecurityConfigurers must be unique. Order of "
                            + order + " was already used on " + previousConfig + ", so it cannot be used on "
                            + config + " too.");
        }
        previousOrder = order;
        previousConfig = config;
    }
    for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
        webSecurity.apply(webSecurityConfigurer);
    }
    this.webSecurityConfigurers = webSecurityConfigurers;
}
```
从这里我们就知道他们的关系了， 这个webSecurityConfigurers是通过spring注入进去的（尼玛，我都快整蒙圈了），他就代表那个过滤器链，也就是权限控制的关键，而我们一开始看到的Websecurity就是这个过滤器链的入口，由它来一个个的将
过过滤器链引用作为自己的成员变量，好了，他们之间的关系我们搞清楚了，接下来就又多了一个新问题，那个过滤器链又是在哪里给初始化了呢。
> @Value("#{@autowiredWebSecurityConfigurersIgnoreParents.getWebSecurityConfigurers()}")

这个el表达式的bean同样在这个配置类中：
```java
@Bean
public static AutowiredWebSecurityConfigurersIgnoreParents autowiredWebSecurityConfigurersIgnoreParents(
        ConfigurableListableBeanFactory beanFactory) {
    return new AutowiredWebSecurityConfigurersIgnoreParents(beanFactory);
}
```
那我们继续看这个AutowiredWebSecurityConfigurersIgnoreParents，它拿到了spring的容器beanFactory，然后得到了那个过滤器链，然后我还是太天真：
```java
@SuppressWarnings({ "rawtypes", "unchecked" })
	public List<SecurityConfigurer<Filter, WebSecurity>> getWebSecurityConfigurers() {
		List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers = new ArrayList<SecurityConfigurer<Filter, WebSecurity>>();
		Map<String, WebSecurityConfigurer> beansOfType = beanFactory
				.getBeansOfType(WebSecurityConfigurer.class);
		for (Entry<String, WebSecurityConfigurer> entry : beansOfType.entrySet()) {
			webSecurityConfigurers.add(entry.getValue());
		}
		return webSecurityConfigurers;
	}
```
它居然不是直接初始化的，而是从beanFactory中取出来了所有WebSecurityConfigurer类型的bean，尼玛！那我们接着看实现了WebSecurityConfigurer并且作为bean在spring中已经初始化了类是哪一个，
不着不知道，依照吓一跳，查看类关系，居然又回到了最初的起点：
[springSecurityFilterChain](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo6.png)
**又是它！**，我们继续查看他，终于！我们找到了那个过滤器链！
```java
protected final HttpSecurity getHttp() throws Exception {
    if (http != null) {
        return http;
    }
    
    DefaultAuthenticationEventPublisher eventPublisher = objectPostProcessor
            .postProcess(new DefaultAuthenticationEventPublisher());
    localConfigureAuthenticationBldr.authenticationEventPublisher(eventPublisher);
    
    AuthenticationManager authenticationManager = authenticationManager();
    authenticationBuilder.parentAuthenticationManager(authenticationManager);
    authenticationBuilder.authenticationEventPublisher(eventPublisher);
    Map<Class<? extends Object>, Object> sharedObjects = createSharedObjects();
    
    http = new HttpSecurity(objectPostProcessor, authenticationBuilder,
            sharedObjects);
    if (!disableDefaults) {
        // @formatter:off
        http
            .csrf().and()
            .addFilter(new WebAsyncManagerIntegrationFilter())
            .exceptionHandling().and()
            .headers().and()
            .sessionManagement().and()
            .securityContext().and()
            .requestCache().and()
            .anonymous().and()
            .servletApi().and()
            .apply(new DefaultLoginPageConfigurer<>()).and()
            .logout();
        // @formatter:on
        ClassLoader classLoader = this.context.getClassLoader();
        List<AbstractHttpConfigurer> defaultHttpConfigurers =
                SpringFactoriesLoader.loadFactories(AbstractHttpConfigurer.class, classLoader);
    
        for (AbstractHttpConfigurer configurer : defaultHttpConfigurers) {
            http.apply(configurer);
        }
    }
    configure(http);
    return http;
    }
```
由此方法我们得知，最终的过滤器链是保存在HttpSecuriry中，并且通过spring把所有AbstractHttpConfigurer子类都加入到容器中并且加入到了过滤器链中 ***http:apply(...)*** ：
那我们看下AbstractHttpConfigurer有哪些子类
[springSecurityFilterChain](https://raw.githubusercontent.com/jsbintask22/static/master/images/springsecurity-demo7.png)，
:sob: 终于找到了，顺便看下HttpSecurity构成：
```java
public final class HttpSecurity extends
		AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, HttpSecurity>
		implements SecurityBuilder<DefaultSecurityFilterChain>,
		HttpSecurityBuilder<HttpSecurity> {
	private final RequestMatcherConfigurer requestMatcherConfigurer;
	private List<Filter> filters = new ArrayList<>();
	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;
	private FilterComparator comparator = new FilterComparator();
```
另外从上面那个方法中，我们还看到了一个很熟悉的过滤器：DefaultLoginPageConfigurer，我们查看它。
```java
private DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = new DefaultLoginPageGeneratingFilter();
private DefaultLogoutPageGeneratingFilter logoutPageGeneratingFilter = new DefaultLogoutPageGeneratingFilter();
```
它有两个过滤器，登陆页面和注销页面，我们继续查看登陆页面，这个时候发现一点意外的收获：
```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		boolean loginError = isErrorPage(request);
		boolean logoutSuccess = isLogoutSuccess(request);
		if (isLoginUrlRequest(request) || loginError || logoutSuccess) {
			String loginPageHtml = generateLoginPageHtml(request, loginError,
					logoutSuccess);
			response.setContentType("text/html;charset=UTF-8");
			response.setContentLength(loginPageHtml.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(loginPageHtml);

			return;
		}

		chain.doFilter(request, response);
	}

	private String generateLoginPageHtml(HttpServletRequest request, boolean loginError,
			boolean logoutSuccess) {
		String errorMsg = "Invalid credentials";

		if (loginError) {
			HttpSession session = request.getSession(false);

			if (session != null) {
				AuthenticationException ex = (AuthenticationException) session
						.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
				errorMsg = ex != null ? ex.getMessage() : "Invalid credentials";
			}
		}

		StringBuilder sb = new StringBuilder();

		sb.append("<!DOCTYPE html>\n"
				+ "<html lang=\"en\">\n"
				+ "  <head>\n"
				+ "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n"
				+ "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>Please sign in</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "  </head>\n"
				+ "  <body>\n"
				+ "     <div class=\"container\">\n");

		String contextPath = request.getContextPath();
		if (this.formLoginEnabled) {
			sb.append("      <form class=\"form-signin\" method=\"post\" action=\"" + contextPath + this.authenticationUrl + "\">\n"
					+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n"
					+ createError(loginError, errorMsg)
					+ createLogoutSuccess(logoutSuccess)
					+ "        <p>\n"
					+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
					+ "          <input type=\"text\" id=\"username\" name=\"" + this.usernameParameter + "\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
					+ "        </p>\n"
					+ "        <p>\n"
					+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
					+ "          <input type=\"password\" id=\"password\" name=\"" + this.passwordParameter + "\" class=\"form-control\" placeholder=\"Password\" required>\n"
					+ "        </p>\n"
					+ createRememberMe(this.rememberMeParameter)
					+ renderHiddenInputs(request)
					+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
					+ "      </form>\n");
		}

		if (openIdEnabled) {
			sb.append("      <form name=\"oidf\" class=\"form-signin\" method=\"post\" action=\"" + contextPath + this.openIDauthenticationUrl + "\">\n"
					+ "        <h2 class=\"form-signin-heading\">Login with OpenID Identity</h2>\n"
					+ createError(loginError, errorMsg)
					+ createLogoutSuccess(logoutSuccess)
					+ "        <p>\n"
					+ "          <label for=\"username\" class=\"sr-only\">Identity</label>\n"
					+ "          <input type=\"text\" id=\"username\" name=\"" + this.openIDusernameParameter + "\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
					+ "        </p>\n"
					+ createRememberMe(this.openIDrememberMeParameter)
					+ renderHiddenInputs(request)
					+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
					+ "      </form>\n");
		}

		if (oauth2LoginEnabled) {
			sb.append("<h2 class=\"form-signin-heading\">Login with OAuth 2.0</h3>");
			sb.append(createError(loginError, errorMsg));
			sb.append(createLogoutSuccess(logoutSuccess));
			sb.append("<table class=\"table table-striped\">\n");
			for (Map.Entry<String, String> clientAuthenticationUrlToClientName : oauth2AuthenticationUrlToClientName.entrySet()) {
				sb.append(" <tr><td>");
				String url = clientAuthenticationUrlToClientName.getKey();
				sb.append("<a href=\"").append(contextPath).append(url).append("\">");
				String clientName = HtmlUtils.htmlEscape(clientAuthenticationUrlToClientName.getValue());
				sb.append(clientName);
				sb.append("</a>");
				sb.append("</td></tr>\n");
			}
			sb.append("</table></div>\n");
		}

		sb.append("</body></html>");

		return sb.toString();
	}
```
我们的helloworld那一篇博客中的登陆页面即来源于此！（还有点惊喜哈:joy:），谈到这，突然记起我们上面谈了一个问题。
@AutoConfigureAfter(SecurityAutoConfiguration.class)为什么要用这个，现在应该知道了吧（:joy:)，因为它要代理的filter在上一个注解。

---
然后我们继续回来看WebSecurity这个构造器（是不是都已经忘记我们是在说这个类的:joy:），这个类很长，我们直接看注释以及主要成员变量
```java
/**
 * <p>
 * The {@link WebSecurity} is created by {@link WebSecurityConfiguration} to create the
 * {@link FilterChainProxy} known as the Spring Security Filter Chain
 * (springSecurityFilterChain). The springSecurityFilterChain is the {@link Filter} that
 * the {@link DelegatingFilterProxy} delegates to.
 * </p>
 *
 * <p>
 * Customizations to the {@link WebSecurity} can be made by creating a
 * {@link WebSecurityConfigurer} or more likely by overriding
 * {@link WebSecurityConfigurerAdapter}.
 * </p>
 *
 * @see EnableWebSecurity
 * @see WebSecurityConfiguration
 *
 * @author Rob Winch
 * @since 3.2
 */
private final Log logger = LogFactory.getLog(getClass());

private final List<RequestMatcher> ignoredRequests = new ArrayList<>();

private final List<SecurityBuilder<? extends SecurityFilterChain>> securityFilterChainBuilders = new ArrayList<SecurityBuilder<? extends SecurityFilterChain>>();

private IgnoredRequestConfigurer ignoredRequestRegistry;

private FilterSecurityInterceptor filterSecurityInterceptor;

private HttpFirewall httpFirewall;

private boolean debugEnabled;

private WebInvocationPrivilegeEvaluator privilegeEvaluator;

private DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();

private SecurityExpressionHandler<FilterInvocation> expressionHandler = defaultWebSecurityExpressionHandler;

private Runnable postBuildAction = new Runnable() {
    public void run() {
    }
};
```
大概意思就是说这个类是被专门用来创建FilterChainProxy，即我们所知道的（springSecurityFilterChain），然后它的配置均来自于
WebSecurityConfigurer，默认实现是WebSecurityConfigurerAdapter，**这是它第N次出现了！**
接下来我们研究下它的主要成员变量，List<RequestMatcher> ignoredRequests = new ArrayList<>();一个匹配请求url的处理器，这处的作用是用来存储我们要忽略的url（不走springsecurity的过滤器链），
FilterSecurityInterceptor，过滤器链就是由它来调用的，HttpFirewall，看名字就知道起到了额外的配置作用（事实上初始化是一个空对象）。
securityFilterChainBuilders可以看成是WebSecurity内部过滤器链的引用。
defaultWebSecurityExpressionHandler是springsecurity el表达式处理器（后面讲解注解时我们再来回顾），比如说 ***hasAnyAuthority(...)***，就可以由它来处理
另外还有一个 WebInvocationPrivilegeEvaluator，它叫做权限计算器，其实就是和防火墙一样，多了一层判断，它的默认实现是
> public class DefaultWebInvocationPrivilegeEvaluator implements WebInvocationPrivilegeEvaluator {

表示所有用户都由权限（因为是默认的）

最后，还有最后一个配置类**UserDetailsServiceAutoConfiguration**
## UserDetailsServiceAutoConfiguration
```java
@Configuration
@ConditionalOnClass(AuthenticationManager.class)
@ConditionalOnBean(ObjectPostProcessor.class)
@ConditionalOnMissingBean({ AuthenticationManager.class, AuthenticationProvider.class,
		UserDetailsService.class })
public class UserDetailsServiceAutoConfiguration {

	private static final String NOOP_PASSWORD_PREFIX = "{noop}";

	private static final Pattern PASSWORD_ALGORITHM_PATTERN = Pattern
			.compile("^\\{.+}.*$");

	private static final Log logger = LogFactory
			.getLog(UserDetailsServiceAutoConfiguration.class);

	@Bean
	@ConditionalOnMissingBean(type = "org.springframework.security.oauth2.client.registration.ClientRegistrationRepository")
	@Lazy
	public InMemoryUserDetailsManager inMemoryUserDetailsManager(
			SecurityProperties properties,
			ObjectProvider<PasswordEncoder> passwordEncoder) {
		SecurityProperties.User user = properties.getUser();
		List<String> roles = user.getRoles();
		return new InMemoryUserDetailsManager(User.withUsername(user.getName())
				.password(getOrDeducePassword(user, passwordEncoder.getIfAvailable()))
				.roles(StringUtils.toStringArray(roles)).build());
	}

	private String getOrDeducePassword(SecurityProperties.User user,
			PasswordEncoder encoder) {
		String password = user.getPassword();
		if (user.isPasswordGenerated()) {
			logger.info(String.format("%n%nUsing generated security password: %s%n",
					user.getPassword()));
		}
		if (encoder != null || PASSWORD_ALGORITHM_PATTERN.matcher(password).matches()) {
			return password;
		}
		return NOOP_PASSWORD_PREFIX + password;
	}

}
```
这次这个配置很简单，因为我们没有配置oauth2，所以它帮我们做了一个UserDetails，并且是根据我们配置的用户密码，把他们load到内存（因为没有db），以后的权限判断就根据
userDetails来判断了，由此可知，如果我们要扩展，实现该类也是必然的。


# 总结
这次，我们从源码的角度查看了springboot帮我们做的配置，并且只得到了login页面的来源，接下来，我们就探究下springsecurity的具体配置！

