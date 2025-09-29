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

