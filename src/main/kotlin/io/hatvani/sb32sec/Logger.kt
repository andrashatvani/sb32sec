package io.hatvani.sb32sec

import org.slf4j.Logger
import org.slf4j.LoggerFactory

@SuppressWarnings("fb-contrib:UP_UNUSED_PARAMETER") // false positive
inline fun <reified T> T.logger(): Logger {
    return LoggerFactory.getLogger(T::class.java)
}
