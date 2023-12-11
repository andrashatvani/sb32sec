package io.hatvani.sb32sec

import io.hatvani.sb32sec.Router.Companion.HANDLER_ENDPOINT
import io.hatvani.sb32sec.security.SecurityConfiguration.Companion.ROLE_USER
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.TestConstructor
import org.springframework.test.context.TestConstructor.AutowireMode.ALL
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.test.web.reactive.server.WebTestClient

@ExtendWith(SpringExtension::class)
@SpringBootTest(
    webEnvironment = RANDOM_PORT,
    classes = [Application::class],
    properties = ["spring.main.allow-bean-definition-overriding=true"]
)
@TestConstructor(autowireMode = ALL)
@WithMockUser(authorities = [ROLE_USER])
class HandlerIntegrationTest(
    private val client: WebTestClient,
) {
    @Test
    fun `shpuld pass`() {
        client.get()
            .uri { it.path(HANDLER_ENDPOINT).build() }
            .exchange()
            .expectStatus()
            .isOk

    }
}
