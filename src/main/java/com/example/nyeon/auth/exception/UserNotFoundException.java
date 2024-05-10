package com.example.nyeon.auth.exception;

import com.example.nyeon.auth.exception.NotFoundException;

public class UserNotFoundException extends NotFoundException{
    private static final String message = "User not exist.";
    public UserNotFoundException() {
        super(message);
    }
}
