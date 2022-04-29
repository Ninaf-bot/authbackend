package com.authenticationtest.authbackend.securityconfig;

import com.authenticationtest.authbackend.Entity.User;
import com.authenticationtest.authbackend.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsRepository implements UserDetailsService {
    @Autowired
    UserRepository  userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user=userRepository.findByUsername(username);
        UserDetails userDetails=new UserDetailsPrincipal(user);
        return userDetails;
    }

}
