package `in`.neuw.oauth2.config

import `in`.neuw.oauth2.util.security.SSLContextHelper
import io.netty.handler.ssl.SslContext
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.util.StringUtils
import javax.annotation.PostConstruct
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory

@ConfigurationProperties(prefix = "oauth2.client")
class OAuth2ClientSSLPropertiesConfigurer {

    private var registration: Map<String, SslConfiguration> = hashMapOf()

    private var trustManagerFactories: MutableMap<String, TrustManagerFactory> = mutableMapOf()

    private var keyManagerFactories: MutableMap<String, KeyManagerFactory> = mutableMapOf()

    private var sslContexts: MutableMap<String, SslContext> = mutableMapOf()

    fun getRegistration(): Map<String, SslConfiguration>? {
        return registration
    }

    fun getSslContexts(): Map<String, SslContext>? {
        return sslContexts
    }

    @PostConstruct
    fun validate() {
        registration.entries.forEach{ (key, value) ->
            run {
                validateRegistration(key, value);
            }
        }
    }

    private fun validateRegistration(registrationKey:String, registration: SslConfiguration) {
        if (registration.sslEnabled) {
            // validate the presence of the other properties
            check(StringUtils.hasText(registration.keystore)) { "keystore must not be empty." }
            check(StringUtils.hasText(registration.keystorePassword)) { "keystore-password must not be empty." }
            check(StringUtils.hasText(registration.truststore)) { "truststore must not be empty." }
            check(StringUtils.hasText(registration.truststorePassword)) { "truststore-password must not be empty." }
            // configure the trustManagerFactories, keyManagerFactories & the sslContexts
            var kmf: KeyManagerFactory = SSLContextHelper.getKeyStore(registration.keystore, registration.keystorePassword)
            keyManagerFactories[registrationKey] = kmf
            var tmf: TrustManagerFactory = SSLContextHelper.getTrustStore(registration.truststore, registration.truststorePassword)
            trustManagerFactories[registrationKey] = tmf
            var sslContext:SslContext = SSLContextHelper.sslContext(kmf, tmf)
            sslContexts[registrationKey] = sslContext
        }
    }

    class SslConfiguration {

        var sslEnabled: Boolean = false

        var keystore: String = ""

        var keystorePassword: String = ""

        var truststore: String = ""

        var truststorePassword: String = ""

    }

}