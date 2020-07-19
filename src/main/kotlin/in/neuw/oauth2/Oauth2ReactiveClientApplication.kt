package `in`.neuw.oauth2

import `in`.neuw.oauth2.config.OAuth2ClientSSLPropertiesConfigurer
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication(exclude = [ReactiveUserDetailsServiceAutoConfiguration::class])
@EnableConfigurationProperties(OAuth2ClientSSLPropertiesConfigurer::class)
class Oauth2ReactiveClientApplication

fun main(args: Array<String>) {
    runApplication<Oauth2ReactiveClientApplication>(*args)
}
