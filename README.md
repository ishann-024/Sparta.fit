this is in our service but check if you are routing it correctly to login page.
I am attaching app-routes.ts 
I am also giving you my html where you can call the function
  logout(): Observable<any> {
    return this.http.post(
      `${this.apiUrl}/auth/logout`, 
      {}, 
      { withCredentials: true }
    ).pipe(
      tap(() => {
        // Redirect to login page after successful logout
        this.router.navigate(['/login']);
      })
    );
  }


export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  {
    path: 'dashboard', component: Dashboard,
    children: [
      { path: 'employee-login', component: EmployeeLogin },
      { path: 'candidate-login', component: CandidateLogin },
      { path: 'candidate-registration', component: CandidateRegistration },
    ]
  },

    { path: 'candidateDashboard', redirectTo: 'candidateDashboard/overview', pathMatch: 'full' },

  {
    path: 'candidateDashboard',
    component: CandidateDashboard,
    children: [
      {
        path: 'overview',
        component: Overview, // Your default dashboard
      },
      {
        path: 'my-applications',
        component: CandidateMyapplications,
      },
      {
        path: 'find-jobs',
        component: FindJobs,
      },
      {
        path: 'interviews',
        component: Interviews,
      },
      {
        path: 'edit-profile',
        component: CandidateEditProfile,
      },
      {
        path: 'settings',
        component: Settings,
      },
    ],
  },


  { path: 'tl-dashboard', redirectTo: 'tl-dashboard/overview', pathMatch: 'full' },


  {
    path: 'tl-dashboard',
    component: TeamleadDashboard,
    children: [
      {
        path: 'overview',
        component: TlOverview, // Your default dashboard
      },
      {
        path: 'my-projects',
        component: MyProject,
      },
      {
        path: 'job-requests',
        component: JobRequest,
      },
      {
        path: 'team-members',
        component: TeamMembers,
      },
      {
        path: 'pending-interviews',
        component: PendingInterviews,
      },
      {
        path: 'settings',
        component: TlSettings,
      },
    ],
  },



  { path: 'pm-dashboard', redirectTo: 'pm-dashboard/overview', pathMatch: 'full' },


  {
    path: 'pm-dashboard',
    component: PmDashboard,
    children: [
      {
        path: 'overview',
        component: PmOverview, // Your default dashboard
      },
      {
        path: 'assign-project',
        component: AssignProject,
      },
      {
        path: 'job-requests',
        component: PmJobRequests,
      },
      {
        path: 'bench-employees',
        component: BenchEmployees,
      },
      {
        path: 'team-members',
        component: PmTeamMembers,
      },
      {
        path: 'pending-interviews',
        component: PmPendingInterviews,
      },
      {
        path: 'settings',
        component: PmSettings,
      },
    ],
  },

  { path: 'hr-dashboard', component: HrDashboard },

  { path: 'hr-dashboard', redirectTo: 'hr-dashboard/overview', pathMatch: 'full' },


  {
    path: 'hr-dashboard',
    component: HrDashboard,
    children: [
      {
        path: 'overview',
        component: HrOverview, 
      },
      {
        path: 'job-requests',
        component: HrJobRequests,
      },
      {
        path: 'applied-candidates',
        component: AppliedCandidates,
      },
      {
        path: 'shortlisted-candidates',
        component: ShortlistedCandidates,
      },
      {
        path: 'interviews',
        component: HrInterviews,
      },
      {
        path: 'settings',
        component: HrSettings,
      },
    ],
  },

  { path: '**', redirectTo: 'candidate-login' }

];


  logout(): Observable<any> {
    return this.http.post(
      `${this.apiUrl}/auth/logout`, 
      {}, 
      { withCredentials: true }
    ).pipe(
      tap(() => {
        // Redirect to login page after successful logout
        this.router.navigate(['/login']);
      })
    );
  }

  Dashboard : 
  <!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Jobie - Team Lead Dashboard</title>
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
      rel="stylesheet"
    />
    <link
      href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"
      rel="stylesheet"
    />
  </head>
  <body>
    <div class="dashboard-container">
      <!-- Sidebar -->
      <aside class="sidebar">
        

        <div class="user-profile">
          <div class="user-avatar">SJ</div>
          <div class="user-info">
            <h3>Sarah Johnson</h3>
            <p>Team Lead - Frontend</p>
          </div>
        </div>

        <nav>
          <ul class="nav-menu">
            <li class="nav-item">
              <a
                routerLink="/tl-dashboard/overview"
                routerLinkActive="active"
                [routerLinkActiveOptions]="{ exact: true }"
                class="nav-link"
              >
                <i class="fas fa-home"></i>
                <span>Dashboard</span>
              </a>
            </li>
            <li class="nav-item">
              <a
                routerLink="/tl-dashboard/my-projects"
                routerLinkActive="active"
                [routerLinkActiveOptions]="{ exact: true }"
                class="nav-link"
              >
                <i class="fas fa-project-diagram"></i>
                <span>My Projects</span>
              </a>
            </li>
            <li class="nav-item">
              <a
                routerLink="/tl-dashboard/job-requests"
                routerLinkActive="active"
                [routerLinkActiveOptions]="{ exact: true }"
                class="nav-link"
              >
                <i class="fas fa-clipboard-list"></i>
                <span>Job Requests</span>
              </a>
            </li>
            <li class="nav-item">
              <a
                routerLink="/tl-dashboard/team-members"
                routerLinkActive="active"
                [routerLinkActiveOptions]="{ exact: true }"
                class="nav-link"
              >
                <i class="fas fa-user-friends"></i>
                <span>Team Members</span>
              </a>
            </li>
            <li class="nav-item">
              <a
                routerLink="/tl-dashboard/pending-interviews"
                routerLinkActive="active"
                [routerLinkActiveOptions]="{ exact: true }"
                class="nav-link"
              >
                <i class="fas fa-calendar-alt"></i>
                <span>Pending Interviews</span>
              </a>
            </li>
            <li class="nav-item">
              <a
                routerLink="/tl-dashboard/settings"
                routerLinkActive="active"
                [routerLinkActiveOptions]="{ exact: true }"
                class="nav-link"
              >
                <i class="fas fa-cog"></i>
                <span>Settings</span>
              </a>
            </li>
            <li class="nav-item">
              <a href="Logout" class="nav-link">
                <i class="fas fa-sign-out-alt"></i>
                <span>Logout</span>
              </a>
            </li>
          </ul>
        </nav>
      </aside>

      <!-- Main Content -->
      <main class="main-content">
        <!-- Header -->
        <header class="header">
          <div class="welcome-section">
            <h1 id="welcomeMessage">Welcome Back, Sarah!</h1>
            <p>Lead your team to success and manage projects efficiently</p>
          </div>
         
          <div class="header-actions">
            <!-- <div class="search-box">
              <input type="text" placeholder="Search projects, team members..." id="globalSearch" />
              <i class="fas fa-search"></i>
            </div> -->

            <div class="notification-btn" onclick="toggleNotifications()">
              <i class="fas fa-bell"></i>
              <span class="notification-badge">3</span>
            </div>
          </div>
        </header>

        <section class="content-area">
          <router-outlet></router-outlet>
        </section>
      </main>
    </div>
  </body>
</html>

