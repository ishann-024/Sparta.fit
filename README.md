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
            .body("Logout successful");
    }
}
---------------------------------------------------------------------------------------------------
Is following correct
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.finalproject.main.dto.EmployeeLoginRequest;
import com.finalproject.main.dto.LoginResponse;
import com.finalproject.main.security.UserPrincipal;
import com.finalproject.main.service.CandidateAuthService;
import com.finalproject.main.service.EmployeeAuthService;
import com.finalproject.main.util.JwtTokenUtil;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin("*")
public class AuthController {
	

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private EmployeeAuthService employeeAuthService;

    @Autowired
    private CandidateAuthService candidateAuthService;
    
    //-------------------
    
    @Autowired
    private UserPrincipal userPrincipal;
    
    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;
    @Value("${jwt.expiration.ms:3000000}")
    private long jwtExpirationMs;
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
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        ResponseCookie logoutCookie = createLogoutCookie();
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, logoutCookie.toString())
            .body("Logout successful");
    }
