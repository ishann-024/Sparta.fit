i have successfully implemented JWT + OnlyCookie in my spring backend. Now help me create angular frontend for the same.
I am giving you my authController and TeamLeadController and since i have already created my angular project i am also giving you my tl-service.ts and 
TeamLead-dashboard.ts do not modify Teamlead-dashboard.ts

teamlead-dashboard.ts :
import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink, RouterModule, RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-teamlead-dashboard',
  imports: [RouterOutlet,RouterLink,RouterModule,CommonModule,FormsModule],
  templateUrl: './teamlead-dashboard.html',
  styleUrl: './teamlead-dashboard.css'
})
export class TeamleadDashboard {

}

tl-service.ts : 
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class TlService {
  baseurl: string= "http://localhost:8082/api/team-leader/";
  constructor(private httpClient:HttpClient){
  }
}
TeamLeadController.java : 
@AllArgsConstructor
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
	public ResponseEntity<ProjectResponseDTO> teamLeaderId(Authentication authentication) {
		return ResponseEntity.ok(teamLeadService.getProjectsByTeamLeader(authentication.getName()));
	}
	
    // ---------------------------------------------------------------------------------
	// 2. Create job request
	@PostMapping("/create-job-requests")
	public ResponseEntity<String> createJobRequest(@RequestBody CreateJobRequestDTO dto) {
		teamLeadService.createJobRequest(dto);
		return ResponseEntity.ok("Job Request Created Successfully");
	}

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
AuthController.java : 
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
	If you need any other class tell me 
