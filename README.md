my backend is working perfectly fine help me solve this same for front end. I started by just implemeting only 1 API and commenting other API but I am getting 403 Forbidden in front end

tl-overview.ts:38  GET http://localhost:8082/api/team-leader/pending/job-requests 403 (Forbidden)
Exception Occured While Calling API

I am giving my appconfig.ts , tl-service.ts so that you can find the issue,If you want any other file i'll give
import { ApplicationConfig, provideBrowserGlobalErrorListeners, provideZoneChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';
import { provideHttpClient } from '@angular/common/http';
import { httpInterceptorProviders } from './service/CredentialsInterceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
     provideHttpClient(),
     httpInterceptorProviders
  ]
};

AuthInterceptor : 
import { Injectable } from '@angular/core';
import { HttpInterceptorFn } from '@angular/common/http';
// @Injectable({
//   providedIn: 'root'
// })
// export class AuthInterceptor {
  
// }
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  // Clone the request to add withCredentials for cookies
  const clonedRequest = req.clone({
    withCredentials: true
  });
  
  return next(clonedRequest);
};

employee-login-service.ts : 
import { Component } from '@angular/core';
import {
  FormControl,
  FormGroup,
  FormsModule,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms';
import { Router } from '@angular/router';
import { EmployeeLoginRequest } from '../../dto/EmployeeLoginRequest';
import { CandidateLoginResponseDto } from '../../dto/CandidateLoginResponseDto';
import { EmployeeLoginService } from '../../service/employee-login-service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-employee-login',
  standalone: true,
  imports: [FormsModule, CommonModule],
  templateUrl: './employee-login.html',
  styleUrl: './employee-login.css',
})
export class EmployeeLogin {
  employeeLogin: EmployeeLoginRequest = new EmployeeLoginRequest();
  employeeResponseDTo: CandidateLoginResponseDto = new CandidateLoginResponseDto();
  isLoading: boolean = false; // Added loading state

  constructor(private employeeLoginService: EmployeeLoginService, private router: Router) {}

  loginEmployee() {
    console.log(this.employeeLogin);
    this.isLoading = true;

    this.employeeLoginService.employeeLogin(this.employeeLogin).subscribe({
      next: (data) => {
        console.log(data);
        this.employeeResponseDTo = data;
        console.log(this.employeeResponseDTo);
        if (this.employeeResponseDTo.role == 'TEAMLEAD') {
          this.router.navigate(['tl-dashboard']);
        } else if (this.employeeResponseDTo.role == 'HR') {
          this.router.navigate(['hr-dashboard']);
        } else if (this.employeeResponseDTo.role == 'PROJECTMANAGER') {
          this.router.navigate(['pm-dashboard']);
        } else if (this.employeeResponseDTo.role == 'EMPLOYEE') {
          this.router.navigate(['candidateDashboard']);
        }
      },
      error: (err) => {
        console.log('Exception Occurred While Calling API');
        this.isLoading = false; // Stop loading on error
      },
      complete: () => {
        console.log('Data completed Successfully');
        this.isLoading = false; // Stop loading on completion
      },
    });
  }
}

tl-overview.ts (where we are calling the service) :
import { Component, OnInit } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';
import { TlService } from '../../service/tl-service';

@Component({
  selector: 'app-tl-overview',
  imports: [RouterOutlet,RouterLink],
  templateUrl: './tl-overview.html',
  styleUrl: './tl-overview.css'
})
export class TlOverview implements OnInit {
  pendingJobRequestsCount: number = 0;
  errorMessage: string = '';

  constructor(private tlService: TlService) {}

  ngOnInit(): void {
    this.fetchPendingJobRequestsCount();
  }
  fetchPendingJobRequestsCount(): void { 
    this.tlService.getPendingJobRequestsCount().subscribe({
      next: (data) => {
        this.pendingJobRequestsCount = data;
        console.log(data);
      },
      error: (err) => {
        console.log("Exception Occured While Calling API"); 
        console.log(err.error);
      },
      complete: () => {
        console.log("Data Completed Successfully");
      }
    });
  }
}



Tl-service : 
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
 getPendingJobRequestsCount(): Observable<number> {
    return this.httpClient.get<number>(this.baseurl+"pending/job-requests");
  }
}
