I am getting following error : 
teamlead-dashboard.ts:24 Logout error :  
HttpErrorResponse {headers: _HttpHeaders, status: 200, statusText: 'OK', url: 'http://localhost:8082/api/auth/logout', ok: false, …}
error
: 
{error: SyntaxError: Unexpected token 'L', "Logout successful" is not valid JSON at JSON.parse (<anonym…, text: 'Logout successful'}
headers
: 
_HttpHeaders {headers: undefined, normalizedNames: Map(0), lazyUpdate: null, lazyInit: ƒ}
message
: 
"Http failure during parsing for http://localhost:8082/api/auth/logout"


Service.ts : 
export class AuthService {
  private baseUrl = 'http://localhost:8082/api/auth';

   constructor(private httpClient: HttpClient,private router:Router) {}
    logout(): Observable<any> {
    return this.httpClient.post(
      this.baseUrl+"/logout", 
      {}, 
      { withCredentials: true }
    );
  }

component.ts : 
export class TeamleadDashboard {
  constructor(private authService : AuthService,private router:Router){}
  onLogout(): void{
    this.authService.logout().subscribe({
      next: () => {
        console.log("Logout Successfull");
        this.router.navigate(['/dashboard']);
      },
      error: (error) => {
        console.error('Logout error : ', error);
      }
    });
  }
}

HTML : 
<li class="nav-item">
              <a (click)="onLogout()" class="nav-link" style="cursor: pointer;">
                <i class="fas fa-sign-out-alt"></i>
                <span>Logout</span>
              </a>
            </li>

app-routes.ts : 
{ path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  {
    path: 'dashboard', component: Dashboard,
    children: [
      { path: 'employee-login', component: EmployeeLogin },
      { path: 'candidate-login', component: CandidateLogin },
      { path: 'candidate-registration', component: CandidateRegistration },
    ]
  },


AuthController : 
@RestController
@RequestMapping("/api/auth")
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
