public class CreateCandidateDTO {
	private String email;
	private String password;
	private String fullName;
	private String phoneNumber;
	private String previousRole;
}
public class Candidate {
	private Integer candidateId;
    private String email;
    private String phoneNumber;
    private String profileRole;
    private String imagePath;
    private String passwordHash;
    private String fullName;
    private String gender;
    private Double expectedCtc;
    private String resumePath;
    private Double totalExperience;
    private Integer noticePeriod;
    private String currentCompany;
    private String skills;
    private String status;
    private LocalDate createdAt;
    private LocalDate updatedAt;
	private String otp;
    private LocalDateTime otpGeneratedAt;
}

public class CandidateManualMapper {
	public Candidate toEntity(CreateCandidateDTO dto) {
        if (dto == null) {
            return null;
        }
        Candidate candidate = new Candidate();
        candidate.setEmail(dto.getEmail());
        candidate.setFullName(dto.getFullName());
        candidate.setPhoneNumber(dto.getPhoneNumber());
        candidate.setProfileRole(dto.getPreviousRole());
        candidate.setCreatedAt(LocalDate.now());
        candidate.setStatus("PENDING_VERIFICATION"); // Set initial status
        return candidate;
    }
}
