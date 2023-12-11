package io.hatvani.sb32sec

import io.hatvani.sb32sec.Router.Companion.HANDLER_ENDPOINT
import io.hatvani.sb32sec.security.DomainSecurityConfiguration
import io.hatvani.sb32sec.security.SecurityConfiguration.Companion.ROLE_USER
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod.OPTIONS
import org.springframework.security.config.web.server.AuthorizeExchangeDsl
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers
import org.springframework.stereotype.Component
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsWebFilter
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource

@Configuration
class CorsConfiguration {

    @Bean
    fun corsWebFilter(): CorsWebFilter {
        val cc = CorsConfiguration().apply {
            allowedOrigins = listOf("*")
            allowedHeaders = listOf("*")
            allowedMethods = listOf("*")
        }

        return CorsWebFilter(UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("$HANDLER_ENDPOINT/**", cc)
        })
    }
}

@Component
class AnhangSecurityConfiguration : DomainSecurityConfiguration {

    override fun configure(dsl: AuthorizeExchangeDsl) {
        dsl.apply {
            authorize(pathMatchers(OPTIONS, "$HANDLER_ENDPOINT/**"), permitAll)
            authorize("$HANDLER_ENDPOINT/**", hasAuthority(ROLE_USER))
        }
    }
}