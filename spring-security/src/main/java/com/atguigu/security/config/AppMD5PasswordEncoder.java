package com.atguigu.security.config;

import com.atguigu.security.service.MD5Util;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author erdong
 * @create 2019-09-19 19:16
 */
public class AppMD5PasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence charSequence) {
        // 可以使用自己的加密方法对传入的密码进行加密处理
        return MD5Util.digest(charSequence.toString());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        String loginPwd = encode(rawPassword);
        return loginPwd.equals(encodedPassword);
    }
}
