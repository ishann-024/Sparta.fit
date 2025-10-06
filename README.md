Now help me with HTML and CSS on clicking Create job request a form should pop up which should take following feilds from the DTO
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CreateJobRequestDTO { 
private int projectId;
private String skills;
private int headCount;
private String jobType;
private String title;
private String description;
private String priority;
private int minExperience;
private int maxExperience;
private double minCtc;
private double maxCtc;
}
and on clicking create button following API should be called 
@PostMapping("/create-job-requests") public ResponseEntity<String> createJobRequest(@RequestBody CreateJobRequestDTO dto,Authentication authentication) { dto.setTeamLeaderId(authentication.getName()); 
teamLeadService.createJobRequest(dto);
return ResponseEntity.ok("Job Request Created Successfully"); 
}
on clicking create job request button the form should appear 
<!-- Create Job Request Button --> 
section class="page-header"
	br button class="btn-primary" onclick="openCreateJobRequestModal()"
		i class="fas fa-plus" /i Create New Request /button
/section


@Transactional(readOnly = true)
	public String createJobRequest(CreateJobRequestDTO dto) {
		// get project by same for TL and PM
		int projectId = teamLeadRepository.getProjectIdForCreateJobRequest(dto.getTeamLeaderId());
		dto.setProjectId(projectId);
		// Get the Project Manager who created this project
		String pmId = teamLeadRepository.findProjectManagerIdByProject(dto.getProjectId());
		dto.setPmId(pmId);
		
		return teamLeadRepository.createJobRequest(dto.getTeamLeaderId(), pmId, dto);
	}





	<body>
    <div class="applications-container">
        <!-- Header Section -->
        <section class="applications-header">
            <div class="header-content">
                <h1 class="page-title">Job Requests</h1>
                <p class="page-subtitle">Create and manage resource requests for your projects</p>
                <div class="applications-stats">
                    <div class="stat-item stats-total">
                        <div class="stat-number">{{allJobRequestCount}}</div>
                        <div class="stat-label">Total Job Requests</div>
                    </div>
                    <div class="stat-item stats-approved">
                        <div class="stat-number">{{approvedJobRequestsCount}}</div>
                        <div class="stat-label">Approved</div>
                    </div>
                    <div class="stat-item stats-declined">
                        <div class="stat-number">{{declinedJobRequestsCount}}</div>
                        <div class="stat-label">Declined</div>
                    </div>
                    <div class="stat-item stats-pending">
                        <div class="stat-number">{{pendingJobRequest}}</div>
                        <div class="stat-label">Pending</div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Create Job Request Button -->
        <section class="page-header">
            <br>
            <button class="btn-primary" onclick="openCreateJobRequestModal()">
                <i class="fas fa-plus"></i> Create New Request
            </button>
        </section>

        <!-- Job Requests Grid -->
        <section class="cards-grid">
            <!-- Example Job Request Card -->
            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">React Developer Required</div>
                        <div class="card-subtitle">JR001 • E-commerce Platform</div>
                    </div>
                    <span class="status-badge status-approved">Approved</span>
                </div>
                <div class="card-content">
                    <div class="info-row">
                        <span class="info-label">Project:</span>
                        <span class="info-value">E-commerce Platform</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Required Skills:</span>
                        <span class="info-value">React, Node.js, MongoDB</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Experience:</span>
                        <span class="info-value">3+ years</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Quantity:</span>
                        <span class="info-value">2 Developers</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Status:</span>
                        <span class="info-value">Posted on Job Portal</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Applications:</span>
                        <span class="info-value">15 candidates applied</span>
                    </div>
                </div>
                <div class="card-actions">
                    <button class="btn-sm btn-primary">
                        <i class="fas fa-users"></i> View Candidates
                    </button>
                    <button class="btn-sm btn-edit" onclick="editJobRequest('JR001')">
                        <i class="fas fa-edit"></i> Edit Request
                    </button>
                </div>
            </div>
            <!--Hard Coded Job requests -->
            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">UI/UX Designer</div>
                        <div class="card-subtitle">JR002 • E-commerce Platform</div>
                    </div>
                    <span class="status-badge status-pending">Pending Approval</span>
                </div>
                <div class="card-content">
                    <div class="info-row">
                        <span class="info-label">Project:</span>
                        <span class="info-value">E-commerce Platform</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Required Skills:</span>
                        <span class="info-value">Figma, Adobe XD, Prototyping</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Experience:</span>
                        <span class="info-value">2+ years</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Quantity:</span>
                        <span class="info-value">1 Designer</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Submitted:</span>
                        <span class="info-value">Oct 20, 2024</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Urgency:</span>
                        <span class="info-value">Medium</span>
                    </div>
                </div>
                <div class="card-actions">
                    <button class="btn btn-warning btn-sm">
                        <i class="fas fa-clock"></i> Waiting for PM Approval
                    </button>
                    <button class="btn btn-edit" onclick="editJobRequest('JR002')">
                        <i class="fas fa-edit"></i> Edit Request
                    </button>
                </div>
            </div>
        </section>
    </div>
</body>


---------------------------------------------------
@RestController
@RequestMapping("/api/auth")
//@CrossOrigin(origins = "*", allowCredentials = "true")
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
		return ResponseCookie.from("jwt-token", jwt).httpOnly(true).secure(cookieSecure).path("/")
				.maxAge(jwtExpirationMs / 1000).sameSite("Lax").build();
	}

	private ResponseCookie createLogoutCookie() {
		return ResponseCookie.from("jwt-token", "").httpOnly(true).secure(cookieSecure).path("/").maxAge(0)
				.sameSite("Lax").build();
	}

	@PostMapping("/login/employee")
	public ResponseEntity<?> loginEmployee(@RequestBody EmployeeLoginRequest loginRequest) {
		try {
			// Authenticate the user
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(loginRequest.getEmployeeId(), loginRequest.getPassword()));

			// Set authentication in security context
			SecurityContextHolder.getContext().setAuthentication(authentication);

			// Load user details to get UserPrincipal
			UserPrincipal userPrincipal = (UserPrincipal) employeeAuthService
					.loadUserByUsername(loginRequest.getEmployeeId());

			// Generate JWT token
			String jwt = jwtTokenUtil.generateToken(userPrincipal);
			ResponseCookie jwtCookie = createJwtCookie(jwt);

			// Create response
			LoginResponse res = new LoginResponse(null, // Token not in response body
					userPrincipal.getUserId(), userPrincipal.getFullName(), userPrincipal.getRole(), "EMPLOYEE");

			System.out.println("Employee login successful: " + loginRequest.getEmployeeId());

			return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body(res);

		} catch (BadCredentialsException e) {
			System.out.println("Employee login failed: " + loginRequest.getEmployeeId());
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Login error: " + e.getMessage());
		}
	}

	@PostMapping("/login/candidate")
	public ResponseEntity<?> loginCandidate(@RequestBody CandidateLoginRequest loginRequest) {
		try {
			// Authenticate the user
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

			// Set authentication in security context
			SecurityContextHolder.getContext().setAuthentication(authentication);

			// Load user details to get UserPrincipal
			UserPrincipal userPrincipal = (UserPrincipal) candidateAuthService
					.loadUserByUsername(loginRequest.getEmail());

			// Generate JWT token
			String jwt = jwtTokenUtil.generateToken(userPrincipal);
			ResponseCookie jwtCookie = createJwtCookie(jwt);

			// Create response
			LoginResponse res = new LoginResponse(null, // Token not in response body
					userPrincipal.getUserId(), userPrincipal.getFullName(), userPrincipal.getRole(), "CANDIDATE");

			System.out.println("Candidate login successful: " + loginRequest.getEmail());

			return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body(res);

		} catch (BadCredentialsException e) {
			System.out.println("Candidate login failed: " + loginRequest.getEmail());
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Login error: " + e.getMessage());
		}
	}

	@PostMapping("/logout")
	public ResponseEntity<?> logout() {
		ResponseCookie logoutCookie = createLogoutCookie();
		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, logoutCookie.toString()).body("Logout successful");
	}
</html>

When I put @Autowired PasswordEncoder passwordEncoder in EmployeeAuthService i am getting following error : 
Description:
***************************
APPLICATION FAILED TO START
***************************

Description:

The dependencies of some of the beans in the application context form a cycle:

   jwtAuthFilter defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\config\JwtAuthFilter.class]
┌─────┐
|  employeeAuthService defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\service\EmployeeAuthService.class]
↑     ↓
|  securityConfig defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\config\SecurityConfig.class]
└─────┘


Action:

Relying upon circular references is discouraged and they are prohibited by default. Update your application to remove the dependency cycle between beans. As a last resort, it may be possible to break the cycle automatically by setting spring.main.allow-circular-references to true.


@Service
public class EmployeeAuthService implements UserAuthService {
	// @Autowired
	private final EmployeeRepository employeeRepository;

	// @Autowired
	private final PasswordEncoder passwordEncoder;
	
	

	public EmployeeAuthService(EmployeeRepository employeeRepository, PasswordEncoder passwordEncoder) {
		super();
		this.employeeRepository = employeeRepository;
		this.passwordEncoder = passwordEncoder;
	}



	@Override
	public UserPrincipal loadUserByUsername(String employeeId) throws UsernameNotFoundException {
		// Find employee by employee_id (not email)
		Employee employee = employeeRepository.findByEmployeeId(employeeId);
		return new UserPrincipal(employee);
	}
	
	@Transactional
    public String changePassword(String employeeId, String currentPassword, String newPassword) {
        Employee employee = employeeRepository.findByEmployeeId(employeeId);
       
        // Verify current password
        if (!passwordEncoder.matches(currentPassword, employee.getPasswordHash())) {
            throw new RuntimeException("Current password is incorrect");
        }
       
        // Validate new password
        if (newPassword == null || newPassword.trim().isEmpty()) {
            throw new RuntimeException("New password cannot be empty");
        }
       
        if (newPassword.length() < 6) {
            throw new RuntimeException("New password must be at least 6 characters long");
        }
       
        // Check if new password is same as current password
        if (passwordEncoder.matches(newPassword, employee.getPasswordHash())) {
            throw new RuntimeException("New password cannot be same as current password");
        }
       
        // Hash and update new password
        String newPasswordHash = passwordEncoder.encode(newPassword);
        employeeRepository.updatePasswordHash(employeeId, newPasswordHash);
       
        return "Password changed successfully";
    }

}

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    //@Autowired
    private JwtAuthFilter jwtAuthFilter;
    
    //@Autowired
    private final EmployeeAuthService employeeAuthService;
    
    //@Autowired 
    private final CandidateAuthService candidateAuthService;
    
    

    public SecurityConfig(EmployeeAuthService employeeAuthService,
			CandidateAuthService candidateAuthService) {
		this.employeeAuthService = employeeAuthService;
		this.candidateAuthService = candidateAuthService;
	}
    
    public void setJwtAuthFilter(JwtAuthFilter jwtAuthFilter) {
    	this.jwtAuthFilter = jwtAuthFilter;
    }

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
            .cors(cors -> cors.configurationSource(corsConfigurationSource())) // CHANGE: Use proper CORS config
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
       
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers(HttpMethod.OPTIONS,"/**").permitAll()
                .requestMatchers("/api/team-leader/**").hasRole("TEAMLEAD")
                .requestMatchers("/api/project-manager/**").hasRole("PROJECTMANAGER")
                .requestMatchers("/api/hr/**").hasRole("HR")
                .requestMatchers("/api/interviewer/**").hasRole("INTERVIEWER")
                .anyRequest().authenticated()
            );

        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // ADD: CORS Configuration for cookie support
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
    	 CorsConfiguration configuration = new CorsConfiguration();
    	    // Use the explicit origin(s) of your frontend application(s)
    	    configuration.setAllowedOrigins(List.of("http://localhost:4200"));
    	    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
    	    configuration.setAllowedHeaders(List.of("*"));
    	    configuration.setAllowCredentials(true);
    	    configuration.setExposedHeaders(List.of(HttpHeaders.SET_COOKIE));
    	    
    	    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    	    source.registerCorsConfiguration("/**", configuration);
    	    return source;
    }
}

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    //@Autowired
    private final JwtTokenUtil jwtTokenUtil;

    //@Autowired
    private final EmployeeAuthService employeeAuthService;

    //@Autowired
    private final CandidateAuthService candidateAuthService;
    
    

    public JwtAuthFilter(JwtTokenUtil jwtTokenUtil, EmployeeAuthService employeeAuthService,
			CandidateAuthService candidateAuthService) {
		super();
		this.jwtTokenUtil = jwtTokenUtil;
		this.employeeAuthService = employeeAuthService;
		this.candidateAuthService = candidateAuthService;
	}

	@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            // CHANGE: Extract JWT from cookie instead of header
            String jwt = getJwtFromCookie(request);
            
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

    // CHANGE: New method to extract JWT from cookie
    private String getJwtFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("jwt-token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    // KEEP: This method for backward compatibility (if some clients still use headers)
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}



***************************
APPLICATION FAILED TO START
***************************
***************************
APPLICATION FAILED TO START
***************************

Description:

The dependencies of some of the beans in the application context form a cycle:

   jwtAuthFilter defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\config\JwtAuthFilter.class]
┌─────┐
|  employeeAuthService defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\service\EmployeeAuthService.class]
↑     ↓
|  securityConfig defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\config\SecurityConfig.class]
└─────┘


Action:

Relying upon circular references is discouraged and they are prohibited by default. Update your application to remove the dependency cycle between beans. As a last resort, it may be possible to break the cycle automatically by setting spring.main.allow-circular-references to true.


@Configuration
public class appConfig {
//	@Bean
//	public BCryptPasswordEncoder getBCryptPasswordEncoder() {
//		return new BCryptPasswordEncoder();
//	}
}




