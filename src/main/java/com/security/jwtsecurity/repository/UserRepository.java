package com.security.jwtsecurity.repository;

import com.security.jwtsecurity.entity.Users;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;


public interface UserRepository extends MongoRepository<Users, String> {

    Optional<Users> findByEmail(String email);

//    Users findByUserName(String userName);

}