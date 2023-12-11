package io.hatvani.sb32sec.security

import java.util.*

data class AuthenticatedUser(
    val id: UUID,
    val roles: List<String>
) {
    fun hasRole(role: String) = roles.contains(role)
}
