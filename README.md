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
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { EmployeeLoginRequest } from '../dto/EmployeeLoginRequest';
import { CandidateLoginResponseDto } from '../dto/CandidateLoginResponseDto';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class EmployeeLoginService {
  

  baseurl: string= "http://localhost:8082/api/auth/";

  constructor(private httpClient:HttpClient){
  }

  employeeLogin(employeeLogin : EmployeeLoginRequest): Observable<CandidateLoginResponseDto>{
    
      return this.httpClient.post<CandidateLoginResponseDto>(this.baseurl + "login/employee",employeeLogin);
    
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
