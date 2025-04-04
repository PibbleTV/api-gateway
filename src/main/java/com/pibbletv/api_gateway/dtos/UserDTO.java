package com.pibbletv.api_gateway.dtos;

import lombok.Data;

@Data
public class UserDTO {
    private Long id;
    private String username;
    private String bgImage;
    private String profileImage;
    private Boolean isBanned;
}
