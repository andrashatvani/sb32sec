package io.hatvani.sb32sec.security

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.stereotype.Component

@Component
@ConfigurationProperties(prefix = "application.monitoring")
class MonitoringProperties {
    lateinit var username: String
    lateinit var password: String
}

