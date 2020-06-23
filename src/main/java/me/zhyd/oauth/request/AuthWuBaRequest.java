package me.zhyd.oauth.request;

import com.alibaba.fastjson.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.GlobalAuthUtils;
import me.zhyd.oauth.utils.UrlBuilder;

/**
 * 58同城登录
 *
 * @author dehua.cao (https://xkcoding.com)
 * @since 1.1.0
 */
public class AuthWuBaRequest extends AuthDefaultRequest {

    public AuthWuBaRequest(AuthConfig config) {
        super(config, AuthDefaultSource.WUBA);
    }

    public AuthWuBaRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.WUBA, authStateCache);
    }

    @Override
    protected AuthToken getAccessToken(AuthCallback authCallback) {
        return AuthToken.builder().accessCode(authCallback.getCode()).build();
    }

    @Override
    protected AuthUser getUserInfo(AuthToken authToken) {
        String response = doPostAuthorizationCode(authToken.getAccessCode());
        JSONObject accessTokenObject = JSONObject.parseObject(response);
        authToken.setAccessToken(accessTokenObject.getString("access_token"));
        authToken.setExpireIn(accessTokenObject.getIntValue("timestamp"));
        authToken.setUid(accessTokenObject.getString("app_key"));
        authToken.setOpenId(accessTokenObject.getString("openid"));

        return AuthUser.builder()
            .uuid(accessTokenObject.getString("app_key"))
            .gender(AuthUserGender.UNKNOWN)
            .token(authToken)
            .source(source.toString())
            .build();
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.9.3
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
            .queryParam("auth_type", "0")
            .queryParam("app_key", config.getClientId())
            .queryParam("redirect_uri", config.getRedirectUri())
            .queryParam("scopes", "1")
            .queryParam("state", getRealState(state))
            .queryParam("platform", "pc")
            .build();
    }
}
