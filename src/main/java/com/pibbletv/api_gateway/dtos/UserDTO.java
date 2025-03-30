package com.pibbletv.api_gateway.dtos;

import lombok.Data;

@Data
public class UserDTO {
    private String uid;
    private String username;
    private String bgPic;
    private String profilePic;
    private boolean isBanned;

}
