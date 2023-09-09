package com.leoni.packaging.security;

import com.leoni.packaging.dto.PostGroupDto;
import com.leoni.packaging.model.AppUser;
import com.leoni.packaging.model.Group;
import com.leoni.packaging.service.GroupService;
import com.leoni.packaging.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.NoSuchElementException;

@Service
@Transactional
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = null;
        try{
            user = userService.findUserByUsername(username);
            return user;
        }catch (NoSuchElementException e){
            throw new UsernameNotFoundException(e.getMessage(),e);
        }
    }
}
