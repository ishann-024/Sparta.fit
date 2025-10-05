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
<section class="page-header">
	<br> <button class="btn-primary" onclick="openCreateJobRequestModal()">
		<i class="fas fa-plus"></i> Create New Request </button> 
</section>
