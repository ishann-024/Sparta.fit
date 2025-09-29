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
