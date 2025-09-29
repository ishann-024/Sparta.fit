HTTPONLY COOKIE


// Import these new classes at the top of your AuthController.java
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

// Your existing AuthController class
@RestController
public class AuthController {

    // ... (Your existing fields like authenticationManager, jwtTokenUtil, etc.)

    @PostMapping("/login/employee")
    public ResponseEntity<?> loginEmployee(@RequestBody EmployeeLoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmployeeId(), loginRequest.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserPrincipal userPrincipal = employeeAuthService.loadUserByUsername(loginRequest.getEmployeeId());

            // 1. Generate the JWT
            String jwt = jwtTokenUtil.generateToken(userPrincipal);

            // 2. Create the HttpOnly cookie
            ResponseCookie jwtCookie = ResponseCookie.from("jwt-token", jwt)
                .httpOnly(true)
                .secure(true) // Should be true in production (HTTPS)
                .path("/")
                .maxAge(24 * 60 * 60) // 1 day
                .build();

            // 3. Create the response object (without the token)
            LoginResponse res = new LoginResponse(null, // Token is now in the cookie, not the body
                                                userPrincipal.getUserId(), 
                                                userPrincipal.getFullName(), 
                                                userPrincipal.getRole(), "EMPLOYEE");
            
            System.out.println("Employee login successful for: " + loginRequest.getEmployeeId());

            // 4. Return the response with the cookie in the header
            return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .body(res);

        } catch (BadCredentialsException e) {
            System.out.println("Employee login failed for: " + loginRequest.getEmployeeId());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }

    @PostMapping("/login/candidate")
    public ResponseEntity<?> loginCandidate(@RequestBody CandidateLoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserPrincipal userPrincipal = candidateAuthService.loadUserByUsername(loginRequest.getEmail());

            // 1. Generate the JWT
            String jwt = jwtTokenUtil.generateToken(userPrincipal);
            
            // 2. Create the HttpOnly cookie
            ResponseCookie jwtCookie = ResponseCookie.from("jwt-token", jwt)
                .httpOnly(true)
                .secure(true) // Should be true in production (HTTPS)
                .path("/")
                .maxAge(24 * 60 * 60) // 1 day
                .build();

            // 3. Create the response object
            LoginResponse res = new LoginResponse(null, // Token is in the cookie
                                                userPrincipal.getUserId(), 
                                                userPrincipal.getFullName(), 
                                                userPrincipal.getRole(), "CANDIDATE");
            
            System.out.println("Candidate login successful for: " + loginRequest.getEmail());

            // 4. Return the response with the cookie in the header
            return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .body(res);

        } catch (BadCredentialsException e) {
            System.out.println("Candidate login failed for: " + loginRequest.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }
}

//-------------------------------------------------------------------------
@RestController
public class AuthController {
    
    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;
    
    @Value("${jwt.expiration.ms:86400000}")
    private long jwtExpirationMs;
    
    // ... your existing fields
    
    private ResponseCookie createJwtCookie(String jwt) {
        return ResponseCookie.from("jwt-token", jwt)
            .httpOnly(true)
            .secure(cookieSecure) // Configurable
            .path("/")
            .maxAge(jwtExpirationMs / 1000) // From properties
            .sameSite("Lax") // CSRF protection
            .build();
    }
    
    private ResponseCookie createLogoutCookie() {
        return ResponseCookie.from("jwt-token", "")
            .httpOnly(true)
            .secure(cookieSecure)
            .path("/")
            .maxAge(0)
            .sameSite("Lax")
            .build();
    }
    
    @PostMapping("/login/employee")
    public ResponseEntity<?> loginEmployee(@RequestBody EmployeeLoginRequest loginRequest) {
        try {
            // ... your existing authentication logic
            
            String jwt = jwtTokenUtil.generateToken(userPrincipal);
            ResponseCookie jwtCookie = createJwtCookie(jwt); // Reusable method
            
            LoginResponse res = new LoginResponse(null, userPrincipal.getUserId(), 
                                                userPrincipal.getFullName(), 
                                                userPrincipal.getRole(), "EMPLOYEE");
            
            return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .body(res);
                
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }
    
    // Similar for loginCandidate...
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        ResponseCookie logoutCookie = createLogoutCookie();
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, logoutCookie.toString())
            .body("Logout s


----'zz------------------------
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.finalproject.main.dto.CandidateLoginRequest;
import com.finalproject.main.dto.EmployeeLoginRequest;
import com.finalproject.main.dto.LoginResponse;
import com.finalproject.main.security.UserPrincipal;
import com.finalproject.main.service.CandidateAuthService;
import com.finalproject.main.service.EmployeeAuthService;
import com.finalproject.main.util.JwtTokenUtil;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", allowCredentials = "true")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private EmployeeAuthService employeeAuthService;

    @Autowired
    private CandidateAuthService candidateAuthService;

    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;
    
    @Value("${jwt.expiration.ms:86400000}") // Default 24 hours
    private long jwtExpirationMs;

    private ResponseCookie createJwtCookie(String jwt) {
        return ResponseCookie.from("jwt-token", jwt)
            .httpOnly(true)
            .secure(cookieSecure)
            .path("/")
            .maxAge(jwtExpirationMs / 1000)
            .sameSite("Lax")
            .build();
    }

    private ResponseCookie createLogoutCookie() {
        return ResponseCookie.from("jwt-token", "")
            .httpOnly(true)
            .secure(cookieSecure)
            .path("/")
            .maxAge(0)
            .sameSite("Lax")
            .build();
    }

    @PostMapping("/login/employee")
    public ResponseEntity<?> loginEmployee(@RequestBody EmployeeLoginRequest loginRequest) {
        try {
            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginRequest.getEmployeeId(), 
                    loginRequest.getPassword()
                )
            );

            // Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // Load user details to get UserPrincipal
            UserPrincipal userPrincipal = (UserPrincipal) employeeAuthService.loadUserByUsername(loginRequest.getEmployeeId());

            // Generate JWT token
            String jwt = jwtTokenUtil.generateToken(userPrincipal);
            ResponseCookie jwtCookie = createJwtCookie(jwt);

            // Create response
            LoginResponse res = new LoginResponse(
                null, // Token not in response body
                userPrincipal.getUserId(), 
                userPrincipal.getFullName(), 
                userPrincipal.getRole(), 
                "EMPLOYEE"
            );

            System.out.println("Employee login successful: " + loginRequest.getEmployeeId());

            return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .body(res);

        } catch (BadCredentialsException e) {
            System.out.println("Employee login failed: " + loginRequest.getEmployeeId());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Login error: " + e.getMessage());
        }
    }

    @PostMapping("/login/candidate")
    public ResponseEntity<?> loginCandidate(@RequestBody CandidateLoginRequest loginRequest) {
        try {
            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginRequest.getEmail(), 
                    loginRequest.getPassword()
                )
            );

            // Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // Load user details to get UserPrincipal
            UserPrincipal userPrincipal = (UserPrincipal) candidateAuthService.loadUserByUsername(loginRequest.getEmail());

            // Generate JWT token
            String jwt = jwtTokenUtil.generateToken(userPrincipal);
            ResponseCookie jwtCookie = createJwtCookie(jwt);

            // Create response
            LoginResponse res = new LoginResponse(
                null, // Token not in response body
                userPrincipal.getUserId(), 
                userPrincipal.getFullName(), 
                userPrincipal.getRole(), 
                "CANDIDATE"
            );

            System.out.println("Candidate login successful: " + loginRequest.getEmail());

            return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .body(res);

        } catch (BadCredentialsException e) {
            System.out.println("Candidate login failed: " + loginRequest.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Login error: " + e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        ResponseCookie logoutCookie = createLogoutCookie();
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, logoutCookie.toString())
            .body("Logout successful");
    }
}

// EmployeeLoginRequest.java
public class EmployeeLoginRequest {
    private String employeeId;
    private String password;
    
    // getters and setters
    public String getEmployeeId() { return employeeId; }
    public void setEmployeeId(String employeeId) { this.employeeId = employeeId; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

// CandidateLoginRequest.java
public class CandidateLoginRequest {
    private String email;
    private String password;
    
    // getters and setters
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

// LoginResponse.java
public class LoginResponse {
    private String token; // Will be null when using cookies
    private String userId;
    private String fullName;
    private String role;
    private String userType;
    
    public LoginResponse(String token, String userId, String fullName, String role, String userType) {
        this.token = token;
        this.userId = userId;
        this.fullName = fullName;
        this.role = role;
        this.userType = userType;
    }
    
    // getters and setters
}




------------------------------
Error starting ApplicationContext. To display the condition evaluation report re-run your application with 'debug' enabled.
[2m2025-09-29T17:26:34.308+05:30[0;39m [31mERROR[0;39m [35m20676[0;39m [2m--- [FinalProject] [  restartedMain] [0;39m[36mo.s.boot.SpringApplication              [0;39m [2m:[0;39m Application run failed

org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration': Injection of autowired dependencies failed
	at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.postProcessProperties(AutowiredAnnotationBeanPostProcessor.java:515) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.populateBean(AbstractAutowireCapableBeanFactory.java:1459) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.doCreateBean(AbstractAutowireCapableBeanFactory.java:606) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.createBean(AbstractAutowireCapableBeanFactory.java:529) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.lambda$doGetBean$0(AbstractBeanFactory.java:339) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultSingletonBeanRegistry.getSingleton(DefaultSingletonBeanRegistry.java:373) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.doGetBean(AbstractBeanFactory.java:337) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.getBean(AbstractBeanFactory.java:202) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultListableBeanFactory.instantiateSingleton(DefaultListableBeanFactory.java:1222) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultListableBeanFactory.preInstantiateSingleton(DefaultListableBeanFactory.java:1188) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultListableBeanFactory.preInstantiateSingletons(DefaultListableBeanFactory.java:1123) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.context.support.AbstractApplicationContext.finishBeanFactoryInitialization(AbstractApplicationContext.java:987) ~[spring-context-6.2.10.jar:6.2.10]
	at org.springframework.context.support.AbstractApplicationContext.refresh(AbstractApplicationContext.java:627) ~[spring-context-6.2.10.jar:6.2.10]
	at org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext.refresh(ServletWebServerApplicationContext.java:146) ~[spring-boot-3.5.5.jar:3.5.5]
	at org.springframework.boot.SpringApplication.refresh(SpringApplication.java:752) ~[spring-boot-3.5.5.jar:3.5.5]
	at org.springframework.boot.SpringApplication.refreshContext(SpringApplication.java:439) ~[spring-boot-3.5.5.jar:3.5.5]
	at org.springframework.boot.SpringApplication.run(SpringApplication.java:318) ~[spring-boot-3.5.5.jar:3.5.5]
	at org.springframework.boot.SpringApplication.run(SpringApplication.java:1361) ~[spring-boot-3.5.5.jar:3.5.5]
	at org.springframework.boot.SpringApplication.run(SpringApplication.java:1350) ~[spring-boot-3.5.5.jar:3.5.5]
	at com.finalproject.main.FinalProjectApplication.main(FinalProjectApplication.java:10) ~[classes/:na]
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method) ~[na:na]
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:77) ~[na:na]
	at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43) ~[na:na]
	at java.base/java.lang.reflect.Method.invoke(Method.java:568) ~[na:na]
	at org.springframework.boot.devtools.restart.RestartLauncher.run(RestartLauncher.java:50) ~[spring-boot-devtools-3.5.5.jar:3.5.5]
Caused by: java.lang.RuntimeException: Could not postProcess org.springframework.security.config.annotation.web.builders.WebSecurity@9fcab6e of type class org.springframework.security.config.annotation.web.builders.WebSecurity
	at org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessor.postProcess(AutowireBeanFactoryObjectPostProcessor.java:71) ~[spring-security-config-6.5.3.jar:6.5.3]
	at org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration.setFilterChainProxySecurityConfigurer(WebSecurityConfiguration.java:159) ~[spring-security-config-6.5.3.jar:6.5.3]
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method) ~[na:na]
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:77) ~[na:na]
	at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43) ~[na:na]
	at java.base/java.lang.reflect.Method.invoke(Method.java:568) ~[na:na]
	at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor$AutowiredMethodElement.inject(AutowiredAnnotationBeanPostProcessor.java:854) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.annotation.InjectionMetadata.inject(InjectionMetadata.java:146) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor.postProcessProperties(AutowiredAnnotationBeanPostProcessor.java:509) ~[spring-beans-6.2.10.jar:6.2.10]
	... 24 common frames omitted
Caused by: org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'mvcHandlerMappingIntrospectorRequestTransformer': Cannot resolve reference to bean 'mvcHandlerMappingIntrospector' while setting constructor argument
	at org.springframework.beans.factory.support.BeanDefinitionValueResolver.resolveReference(BeanDefinitionValueResolver.java:377) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.BeanDefinitionValueResolver.resolveValueIfNecessary(BeanDefinitionValueResolver.java:135) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.ConstructorResolver.resolveConstructorArguments(ConstructorResolver.java:691) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.ConstructorResolver.autowireConstructor(ConstructorResolver.java:206) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.autowireConstructor(AbstractAutowireCapableBeanFactory.java:1395) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.createBeanInstance(AbstractAutowireCapableBeanFactory.java:1232) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.doCreateBean(AbstractAutowireCapableBeanFactory.java:569) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.createBean(AbstractAutowireCapableBeanFactory.java:529) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.lambda$doGetBean$0(AbstractBeanFactory.java:339) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultSingletonBeanRegistry.getSingleton(DefaultSingletonBeanRegistry.java:373) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.doGetBean(AbstractBeanFactory.java:337) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.getBean(AbstractBeanFactory.java:227) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultListableBeanFactory.resolveNamedBean(DefaultListableBeanFactory.java:1605) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultListableBeanFactory.resolveNamedBean(DefaultListableBeanFactory.java:1563) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultListableBeanFactory.resolveBean(DefaultListableBeanFactory.java:563) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultListableBeanFactory$1.getIfUnique(DefaultListableBeanFactory.java:489) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.security.config.annotation.web.builders.WebSecurity.setApplicationContext(WebSecurity.java:433) ~[spring-security-config-6.5.3.jar:6.5.3]
	at org.springframework.context.support.ApplicationContextAwareProcessor.invokeAwareInterfaces(ApplicationContextAwareProcessor.java:110) ~[spring-context-6.2.10.jar:6.2.10]
	at org.springframework.context.support.ApplicationContextAwareProcessor.postProcessBeforeInitialization(ApplicationContextAwareProcessor.java:85) ~[spring-context-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.applyBeanPostProcessorsBeforeInitialization(AbstractAutowireCapableBeanFactory.java:429) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.initializeBean(AbstractAutowireCapableBeanFactory.java:1818) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.initializeBean(AbstractAutowireCapableBeanFactory.java:419) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessor.initializeBeanIfNeeded(AutowireBeanFactoryObjectPostProcessor.java:98) ~[spring-security-config-6.5.3.jar:6.5.3]
	at org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessor.postProcess(AutowireBeanFactoryObjectPostProcessor.java:67) ~[spring-security-config-6.5.3.jar:6.5.3]
	... 32 common frames omitted
Caused by: org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'mvcHandlerMappingIntrospector' defined in class path resource [org/springframework/boot/autoconfigure/web/servlet/WebMvcAutoConfiguration$EnableWebMvcConfiguration.class]: Error creating bean with name 'requestMappingHandlerMapping' defined in class path resource [org/springframework/boot/autoconfigure/web/servlet/WebMvcAutoConfiguration$EnableWebMvcConfiguration.class]: When allowCredentials is true, allowedOrigins cannot contain the special value "*" since that cannot be set on the "Access-Control-Allow-Origin" response header. To allow credentials to a set of origins, list them explicitly or consider using "allowedOriginPatterns" instead.
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.initializeBean(AbstractAutowireCapableBeanFactory.java:1826) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.doCreateBean(AbstractAutowireCapableBeanFactory.java:607) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.createBean(AbstractAutowireCapableBeanFactory.java:529) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.lambda$doGetBean$0(AbstractBeanFactory.java:339) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultSingletonBeanRegistry.getSingleton(DefaultSingletonBeanRegistry.java:373) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.doGetBean(AbstractBeanFactory.java:337) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.getBean(AbstractBeanFactory.java:202) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.BeanDefinitionValueResolver.resolveReference(BeanDefinitionValueResolver.java:365) ~[spring-beans-6.2.10.jar:6.2.10]
	... 55 common frames omitted
Caused by: org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'requestMappingHandlerMapping' defined in class path resource [org/springframework/boot/autoconfigure/web/servlet/WebMvcAutoConfiguration$EnableWebMvcConfiguration.class]: When allowCredentials is true, allowedOrigins cannot contain the special value "*" since that cannot be set on the "Access-Control-Allow-Origin" response header. To allow credentials to a set of origins, list them explicitly or consider using "allowedOriginPatterns" instead.
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.initializeBean(AbstractAutowireCapableBeanFactory.java:1826) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.doCreateBean(AbstractAutowireCapableBeanFactory.java:607) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.createBean(AbstractAutowireCapableBeanFactory.java:529) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.lambda$doGetBean$0(AbstractBeanFactory.java:339) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultSingletonBeanRegistry.getSingleton(DefaultSingletonBeanRegistry.java:373) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.doGetBean(AbstractBeanFactory.java:337) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractBeanFactory.getBean(AbstractBeanFactory.java:202) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.DefaultListableBeanFactory.getBeansOfType(DefaultListableBeanFactory.java:747) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.context.support.AbstractApplicationContext.getBeansOfType(AbstractApplicationContext.java:1426) ~[spring-context-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.BeanFactoryUtils.beansOfTypeIncludingAncestors(BeanFactoryUtils.java:372) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.handler.HandlerMappingIntrospector.initHandlerMappings(HandlerMappingIntrospector.java:159) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.handler.HandlerMappingIntrospector.afterPropertiesSet(HandlerMappingIntrospector.java:146) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.invokeInitMethods(AbstractAutowireCapableBeanFactory.java:1873) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.initializeBean(AbstractAutowireCapableBeanFactory.java:1822) ~[spring-beans-6.2.10.jar:6.2.10]
	... 62 common frames omitted
Caused by: java.lang.IllegalArgumentException: When allowCredentials is true, allowedOrigins cannot contain the special value "*" since that cannot be set on the "Access-Control-Allow-Origin" response header. To allow credentials to a set of origins, list them explicitly or consider using "allowedOriginPatterns" instead.
	at org.springframework.web.cors.CorsConfiguration.validateAllowCredentials(CorsConfiguration.java:568) ~[spring-web-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.handler.AbstractHandlerMethodMapping$MappingRegistry.register(AbstractHandlerMethodMapping.java:652) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.handler.AbstractHandlerMethodMapping.registerHandlerMethod(AbstractHandlerMethodMapping.java:331) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping.registerHandlerMethod(RequestMappingHandlerMapping.java:507) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping.registerHandlerMethod(RequestMappingHandlerMapping.java:84) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.handler.AbstractHandlerMethodMapping.lambda$detectHandlerMethods$2(AbstractHandlerMethodMapping.java:298) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at java.base/java.util.LinkedHashMap.forEach(LinkedHashMap.java:721) ~[na:na]
	at org.springframework.web.servlet.handler.AbstractHandlerMethodMapping.detectHandlerMethods(AbstractHandlerMethodMapping.java:296) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.handler.AbstractHandlerMethodMapping.processCandidateBean(AbstractHandlerMethodMapping.java:265) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.handler.AbstractHandlerMethodMapping.initHandlerMethods(AbstractHandlerMethodMapping.java:224) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.handler.AbstractHandlerMethodMapping.afterPropertiesSet(AbstractHandlerMethodMapping.java:212) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping.afterPropertiesSet(RequestMappingHandlerMapping.java:237) ~[spring-webmvc-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.invokeInitMethods(AbstractAutowireCapableBeanFactory.java:1873) ~[spring-beans-6.2.10.jar:6.2.10]
	at org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory.initializeBean(AbstractAutowireCapableBeanFactory.java:1822) ~[spring-beans-6.2.10.jar:6.2.10]
	... 75 common frames omitted

