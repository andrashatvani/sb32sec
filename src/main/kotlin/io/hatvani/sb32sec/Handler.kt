package io.hatvani.sb32sec

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.buildAndAwait

@Service
class Handler {
    suspend fun get(serverRequest: ServerRequest): ServerResponse = withContext(Dispatchers.IO) {
        ServerResponse.ok().buildAndAwait()
    }
}