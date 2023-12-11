package io.hatvani.sb32sec.security

import org.springframework.security.config.web.server.AuthorizeExchangeDsl

interface DomainSecurityConfiguration {
    fun configure(dsl: AuthorizeExchangeDsl)
}