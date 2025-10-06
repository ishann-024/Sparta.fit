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

The dependencies of some of the beans in the application context form a cycle:

┌─────┐
|  jwtAuthFilter (field private com.finalproject.main.service.EmployeeAuthService com.finalproject.main.config.JwtAuthFilter.employeeAuthService)
↑     ↓
|  employeeAuthService (field private org.springframework.security.crypto.password.PasswordEncoder com.finalproject.main.service.EmployeeAuthService.passwordEncoder)
↑     ↓
|  securityConfig (field private com.finalproject.main.config.JwtAuthFilter com.finalproject.main.config.SecurityConfig.jwtAuthFilter)
└─────┘


Action:

Relying upon circular references is discouraged and they are prohibited by default. Update your application to remove the dependency cycle between beans. As a last resort, it may be possible to break the cycle automatically by setting spring.main.allow-circular-references to true.


