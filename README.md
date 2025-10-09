Help me solve this error : 
Caused by: java.lang.IllegalArgumentException: Property 'dataSource' is required
Caused by: org.springframework.beans.BeanInstantiationException: Failed to instantiate [com.finalproject.main.repository.CandidateRepositoryImpl]: Constructor threw exception
Caused by: org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'candidateRepositoryImpl' defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\repository\CandidateRepositoryImpl.class]: Failed to instantiate [com.finalproject.main.repository.CandidateRepositoryImpl]: Constructor threw exception
Caused by: org.springframework.beans.factory.UnsatisfiedDependencyException: Error creating bean with name 'candidateAuthService' defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\service\CandidateAuthService.class]: Unsatisfied dependency expressed through constructor parameter 0: Error creating bean with name 'candidateRepositoryImpl' defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\repository\CandidateRepositoryImpl.class]: Failed to instantiate [com.finalproject.main.repository.CandidateRepositoryImpl]: Constructor threw exception
Caused by: org.springframework.beans.factory.UnsatisfiedDependencyException: Error creating bean with name 'jwtAuthFilter' defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\config\JwtAuthFilter.class]: Unsatisfied dependency expressed through constructor parameter 2: Error creating bean with name 'candidateAuthService' defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\service\CandidateAuthService.class]: Unsatisfied dependency expressed through constructor parameter 0: Error creating bean with name 'candidateRepositoryImpl' defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\repository\CandidateRepositoryImpl.class]: Failed to instantiate [com.finalproject.main.repository.CandidateRepositoryImpl]: Constructor threw exception
Caused by: org.springframework.beans.factory.UnsatisfiedDependencyException: Error creating bean with name 'jwtAuthFilter' defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\config\JwtAuthFilter.class]: Unsatisfied dependency expressed through constructor parameter 2: Error creating bean with name 'candidateAuthService' defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\service\CandidateAuthService.class]: Unsatisfied dependency expressed through constructor parameter 0: Error creating bean with name 'candidateRepositoryImpl' defined in file [D:\Training\Final\FinalProject\target\classes\com\finalproject\main\repository\CandidateRepositoryImpl.class]: Failed to instantiate [com.finalproject.main.repository.CandidateRepositoryImpl]: Constructor threw exception

Controller :
@PostMapping("create/candidate")
    public ResponseEntity<Candidate> createCandidate(@RequestBody CreateCandidateDTO createCandidateDTO) {
        Candidate newCandidate = candidateService.createCandidate(createCandidateDTO);
        return new ResponseEntity<>(newCandidate, HttpStatus.CREATED);
    }

Service :
public Candidate createCandidate(CreateCandidateDTO createCandidateDTO) {
        Candidate candidate = candidateManualMapper.toEntity(createCandidateDTO);
        // Handle sensitive data and business logic in the service layer
        candidate.setPasswordHash(passwordEncoder.encode(createCandidateDTO.getPassword()));
        return candidateRepository.save(candidate);
    }
Repo :
public Candidate save(Candidate candidate) {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("email", candidate.getEmail());
        parameters.put("full_name", candidate.getFullName());
        parameters.put("phone_number", candidate.getPhoneNumber());
        parameters.put("profile_role", candidate.getProfileRole());
        parameters.put("password_hash", candidate.getPasswordHash());
        parameters.put("status", candidate.getStatus());
        parameters.put("created_at", candidate.getCreatedAt());

        Number newId = simpleJdbcInsert.executeAndReturnKey(parameters);
        candidate.setCandidateId(newId.intValue());

        return candidate;
    }
