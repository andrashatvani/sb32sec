package io.hatvani.sb32sec.security

import io.hatvani.sb32sec.logger
import org.springframework.boot.actuate.autoconfigure.security.reactive.EndpointRequest
import org.springframework.boot.actuate.autoconfigure.security.reactive.EndpointRequest.toAnyEndpoint
import org.springframework.boot.actuate.metrics.export.prometheus.PrometheusScrapeEndpoint
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter
import org.springframework.security.web.server.SecurityWebFilterChain
import reactor.core.publisher.Mono
import java.util.*

@EnableWebFluxSecurity
@Configuration
internal class SecurityConfiguration(
    private val monitoringProperties: MonitoringProperties,
    private val securityProperties: SecurityProperties,
    private val domainSecurityConfiguration: DomainSecurityConfiguration,
) {
    companion object {
        const val AUTHORITY_ACCESS_MONITORING = "AUTHORITY_ACCESS_MONITORING"
        const val AUTHORITY_ACTUATOR = "AUTHORITY_ACTUATOR"
        const val AUTHORITY_ACCESS_INTERNAL_API = "AUTHORITY_ACCESS_INTERNAL_API"

        const val ROLE_USER = "ROLE_USER"
    }

    @Bean
    @ConditionalOnProperty(value = ["spring.security.user.passwordGenerated"], matchIfMissing = true, havingValue = "false")
    fun userDetailsService(): MapReactiveUserDetailsService {
        val actuatorUser = User
            .withUsername(securityProperties.user.name)
            .password("{noop}${securityProperties.user.password}")
            .authorities(AUTHORITY_ACTUATOR, AUTHORITY_ACCESS_MONITORING, AUTHORITY_ACCESS_INTERNAL_API).build()

        val monitoringUser = User
            .withUsername(monitoringProperties.username)
            .password("{noop}${monitoringProperties.password}")
            .authorities(AUTHORITY_ACCESS_MONITORING)
            .build()

        return MapReactiveUserDetailsService(actuatorUser, monitoringUser)
    }

    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            httpBasic { }
            oauth2ResourceServer {
                bearerTokenConverter = ServerBearerTokenAuthenticationConverter().apply { setAllowUriQueryParameter(true) }
                jwt { jwtAuthenticationConverter = KeycloakJwtAuthenticationConverter() }
            }
            csrf { disable() }

            authorizeExchange {
                authorize("/internal/**", hasAuthority(AUTHORITY_ACCESS_INTERNAL_API))
                authorize(EndpointRequest.to("health", "ping", "easyname", "info"), permitAll)
                authorize(EndpointRequest.to(PrometheusScrapeEndpoint::class.java), hasAnyAuthority(
                    AUTHORITY_ACCESS_MONITORING
                ))
                authorize(toAnyEndpoint(), hasAuthority(AUTHORITY_ACTUATOR))
                domainSecurityConfiguration.configure(this)
                authorize(anyExchange, denyAll)
            }
            requestCache { disable() }
        }
    }
}

class KeycloakJwtAuthenticationConverter : Converter<Jwt, Mono<AbstractAuthenticationToken>> {
    private val delegate = JwtAuthenticationConverter()

    override fun convert(jwt: Jwt): Mono<AbstractAuthenticationToken> {
        return Mono.just(jwt)
            .map { source: Jwt -> delegate.convert(source) }
            .map { auth ->
                when (auth) {
                    is JwtAuthenticationToken -> try {
                        KeycloakToken.fromOauth2Token(auth)
                    } catch (e: Exception) {
                        logger().error("Failure while converting token: $e")
                        auth
                    }

                    else -> auth
                }
            }
    }
}

class KeycloakToken(
    authorities: Collection<GrantedAuthority>,
    private val principal: AuthenticatedUser,
    private val credentials: Any,
) : AbstractAuthenticationToken(authorities) {

    companion object {
        fun fromOauth2Token(oauth2Token: JwtAuthenticationToken): KeycloakToken {

            val id = UUID.fromString(oauth2Token.name)
            val jwt = oauth2Token.principal as Jwt

            val realmAccess = jwt.claims["realm_access"] as Map<*, *>
            val roles = (realmAccess["roles"] as List<*>).map { it.toString() }

            val authorities = oauth2Token.authorities.toMutableList()
            authorities.addAll(roles.map { SimpleGrantedAuthority(it) })

            return KeycloakToken(
                authorities = authorities,
                principal = AuthenticatedUser(
                    id = id,
                    roles = roles.toList()
                ),
                credentials = oauth2Token.credentials
            ).apply {
                details = oauth2Token
                isAuthenticated = true
            }
        }
    }

    override fun getPrincipal() = principal

    override fun getCredentials() = credentials
}