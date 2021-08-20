package org.apache.fineract.cn.anubis.security;

import org.springframework.security.core.AuthenticationException;

/**
 * @author manoj
 */
public class AccountLevelAccessDeniedException extends AuthenticationException {
    private AccountLevelAccessDeniedException(final String message) { super(message); }

    public static AccountLevelAccessDeniedException internalError(final String message) {
        return new AccountLevelAccessDeniedException(message);
    }
}
