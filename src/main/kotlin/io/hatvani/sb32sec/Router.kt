package io.hatvani.sb32sec

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.function.server.coRouter

@Configuration
class Router(
    private val handler: Handler,
) {
    companion object {
        const val HANDLER_ENDPOINT = "/api/handle"
    }

    @Bean
    fun route() = coRouter {
        HANDLER_ENDPOINT.nest {
            GET("/", handler::get)
        }
    }
}

