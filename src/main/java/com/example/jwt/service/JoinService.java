package com.example.jwt.service;

import com.example.jwt.dto.JoinDTO;
import com.example.jwt.entity.UserEntity;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDTO joinDTO) {
        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist ) {
            return;
        }

        UserEntity data = new UserEntity(
                username,
                bCryptPasswordEncoder.encode(password),
                "ROLE_ADMIN"
                );

        userRepository.save(data);
    }

}
