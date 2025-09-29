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
In this previous approach we were passing bearer token in Authorization in POstman and then fetching teamleaderId from the token by authentication.getName() but now that we have stored token in Httponly cookie how do these controller change
AllArgsConstructor
@NoArgsConstructor
@RestController
@RequestMapping("/api/team-leader")
@CrossOrigin("*")
public class TeamLeadController {
	@Autowired
	private TeamLeadService teamLeadService;
	
	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	// 1. Get projects assigned to Team Leader
	//	@GetMapping("/projects/{teamLeaderId}")
	//	public ResponseEntity<ProjectResponseDTO> teamLeaderId(@PathVariable("teamLeaderId") String teamLeaderId) {
	//		return ResponseEntity.ok(teamLeadService.getProjectsByTeamLeader(teamLeaderId));
	//	}
	
	// Extract id from jwt ------------------------------------------------------------
	@GetMapping("/projects")
	public ResponseEntity<ProjectResponseDTO> teamLeaderId(String token) {
		return ResponseEntity.ok(teamLeadService.getProjectsByTeamLeader(jwtTokenUtil.getUserIdFromToken(token)));
	}
	
    // ---------------------------------------------------------------------------------
	// 2. Create job request
	@PostMapping("/create-job-requests")
	public ResponseEntity<String> createJobRequest(@RequestBody CreateJobRequestDTO dto) {
		teamLeadService.createJobRequest(dto);
		return ResponseEntity.ok("Job Request Created Successfully");
	}

	// 3. Get all job requests created by TL
	//	@GetMapping("/{teamLeaderId}/job-requests")
	//	public ResponseEntity<List<JobRequest>> getJobRequestsByTeamLeader(@PathVariable("teamLeaderId") String teamLeaderId) {
	//		List<JobRequest> jobRequests = teamLeadService.getJobRequestsByTeamLeader(teamLeaderId);
	//		return ResponseEntity.ok(jobRequests);
	//	}
	
	//------------------------------------------------------------------------
	@GetMapping("/get-job-requests")
		public ResponseEntity<List<JobRequest>> getJobRequestsByTeamLeader(Authentication authentication) {		 
			List<JobRequest> jobRequests = teamLeadService.getJobRequestsByTeamLeader(authentication.getName());
			return ResponseEntity.ok(jobRequests);
		}
	//------------------------------------------------------------------------
	// 4. Update job request by ID
	@PutMapping("/job-requests/{jobRequestId}")
	public ResponseEntity<Boolean> updateJobRequest(@PathVariable("jobRequestId") int jobRequestId,
			@RequestBody UpdateJobRequestDTO dto) {
//		if(teamLeadService.updateJobRequest(jobRequestId, dto)) {
//		return ResponseEntity.ok("Job Request Updated Successfully");
//		}else {
//			return ResponseEntity.ok("Job Request Failed ");
//		}
		return ResponseEntity.status(HttpStatus.CREATED).body(teamLeadService.updateJobRequest(jobRequestId, dto));
	}
	
	@GetMapping("pending/job-requests")
	public ResponseEntity<Integer> getCountActiveJobRequest(Authentication authentication){
		int activeJobRequest = teamLeadService.getPendingJobRequestByTeamLeader(authentication.getName());
		return ResponseEntity.ok(activeJobRequest);
	}
	
	@GetMapping("pending/interviews")
	public ResponseEntity<Integer> getCountPendingInterviews(Authentication authentication){
		int activeJobRequest = teamLeadService.getPendingInterviewsByTeamLeader(authentication.getName());
		return ResponseEntity.ok(activeJobRequest);
	}
	
	@GetMapping("team-members")
	public ResponseEntity<Integer> getCountTeamMembers(Authentication authentication){
		int teamMembers = teamLeadService.getTeamMemberCountByTeamLeaderId(authentication.getName());
		return ResponseEntity.ok(teamMembers);
	}
}

------------- JWT Auth
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private EmployeeAuthService employeeAuthService;

    @Autowired
    private CandidateAuthService candidateAuthService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);
            
            if (StringUtils.hasText(jwt)) {
                if (jwtTokenUtil.validateToken(jwt)) {
                    String username = jwtTokenUtil.getUsernameFromToken(jwt);
                    
                    UserDetails userDetails = null;
                    
                    if (username.startsWith("MGS")) {
                        userDetails = employeeAuthService.loadUserByUsername(username);
                    } else {
                        userDetails = candidateAuthService.loadUserByUsername(username);
                    }
                    
                    if (userDetails != null) {
                        UsernamePasswordAuthenticationToken authentication = 
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        
                        System.out.println("✅ Authenticated user: " + username + " with authorities: " + userDetails.getAuthorities());
                    }
                } else {
                    System.out.println("❌ JWT token validation failed");
                }
            }
        } catch (Exception ex) {
            System.out.println("❌ JWT Filter Error: " + ex.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}

Security Config
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthFilter jwtAuthFilter;
    
    @Autowired
    private EmployeeAuthService employeeAuthService;
    
    @Autowired 
    private CandidateAuthService candidateAuthService;

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(username -> {
            if (username.startsWith("MGS")) {
                return employeeAuthService.loadUserByUsername(username);
            } else {
                return candidateAuthService.loadUserByUsername(username);
            }
        });
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors().and()
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/team-leader/**").hasRole("TEAMLEAD")
                //.requestMatchers("/api/team-leader/**").permitAll()
                .requestMatchers("/api/project-manager/**").hasRole("PROJECTMANAGER")
                .requestMatchers("/api/hr/**").hasRole("HR")
                .requestMatchers("/api/interviewer/**").hasRole("INTERVIEWER")
                .anyRequest().authenticated()
            );

        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
