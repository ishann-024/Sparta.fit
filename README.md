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
</html>

