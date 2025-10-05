I am getting following error : 
:4200/tl-dashboard/settings:1 Access to XMLHttpRequest at 'http://localhost:8082/api/team-leader//auth/logout' from origin 'http://localhost:4200' has been blocked by CORS policy: Response to preflight request doesn't pass access control check: No 'Access-Control-Allow-Origin' header is present on the requested resource.Understand this error
teamlead-dashboard.ts:22 Logout error :  HttpErrorResponse {headers: _HttpHeaders, status: 0, statusText: 'Unknown Error', url: 'http://localhost:8082/api/team-leader//auth/logout', 

loginEmployee @ employee-login.ts:33
EmployeeLogin_Template_form_submit_11_listener @ employee-login.html:14
executeListenerWithErrorHandling @ debug_node.mjs:13155
wrapListenerIn_markDirtyAndPreventDefault @ debug_node.mjs:13144

teamlead-dashboard.ts:16  POST http://localhost:8082/api/team-leader//auth/logout net::ERR_FAILED

service.ts : 
logout(): Observable<any> {
    return this.httpClient.post(
      this.baseurl+"/auth/logout", 
      {}, 
      { withCredentials: true }
    ).pipe(
      tap(() => {
        // Redirect to login page after successful logout
        this.router.navigate(['/dashboard/employee-login']);
      })
    );
  }

  subscribe : 
  onLogout(): void{
    this.tlService.logout().subscribe({
      next: () => {
        console.log("Logout Successfull");
        this.router.navigate(['/dashboard/employee-login']);
      },
      error: (error) => {
        console.error('Logout error : ', error);
      }
    });
  }

  Html : 
  <li class="nav-item">
              <a (click)="onLogout()" class="nav-link" style="cursor: pointer;">
                <i class="fas fa-sign-out-alt"></i>
                <span>Logout</span>
              </a>
            </li>

  Spring controller : 
  RestController
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
  }

  SecurityConfig : 
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

    // ADD: CORS Configuration for cookie suppor
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
