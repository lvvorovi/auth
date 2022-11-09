package com.authserver.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthserverApplication {

    /*
    Call sequance:

    1. In browser
    localhost:9090/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=http://127.0.0.1:3000/authorized&code_challenge=dPz8OFyP8g1yHdxiH6lyoQnALCUbUUclGilMBtf7ksg&code_challenge_method=S256

    user credentials
    username: admin
    password: admin

    3. copy `code` from redirect url

    4. POSTMAN request
    - method:
        POST
    - url:
        http://localhost:9090/oauth2/token?code={code_from_first_request}&redirect_uri=http://127.0.0.1:3000/authorized&grant_type=authorization_code&code_verifier=2iQIug_f4iSFuun2ktC02Yh4TpMykSEUxdNpYk_er2k

    - substitude `{code_from_first_request}` with code acquired from step 3
    - copy jwt provided in the response

    4. POSTMAN request
    - method:
        POST
    - url:
    http://localhost:8080/api/v1/admin/books
        body:
            {
                "name": "book name",
                "author": "Author",
                "price": 10.00
            }
    - authorization:
        Bearer Token
    - authorization value:
        Bearer +jwt acquired in step 4
    * */

    public static void main(String[] args) {
        SpringApplication.run(AuthserverApplication.class, args);
    }

}
