package com.fang.supportportal.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class HttpResponse {
    private int httpStatusCode; // 200
    private HttpStatus httpStatus;
    private String reason;
    private String message;
}
