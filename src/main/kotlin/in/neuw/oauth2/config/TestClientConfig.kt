package `in`.neuw.oauth2.config

import io.netty.channel.ChannelOption
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.reactive.ClientHttpConnector
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder.ClientCredentialsGrantBuilder
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveClientCredentialsTokenResponseClient
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.web.reactive.function.client.ClientRequest
import org.springframework.web.reactive.function.client.ClientResponse
import org.springframework.web.reactive.function.client.ExchangeFilterFunction
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono
import reactor.netty.http.client.HttpClient
import reactor.netty.tcp.SslProvider.SslContextSpec
import java.util.function.Consumer

@Configuration
class TestClientConfig {

    @Autowired
    private lateinit var oAuth2ClientSSLPropertiesConfigurer: OAuth2ClientSSLPropertiesConfigurer

    private val testWebClientLogger: Logger = LoggerFactory.getLogger("TEST_WEB_CLIENT")

    @Bean
    fun authorizedClientManager(
            clientRegistrationRepository: ReactiveClientRegistrationRepository?,
            authorizedClientRepository: ServerOAuth2AuthorizedClientRepository): ReactiveOAuth2AuthorizedClientManager? {

        val authorizedClientProvider: ReactiveOAuth2AuthorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .build()

        val authorizedClientManager = DefaultReactiveOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientRepository)

        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider)
        return authorizedClientManager
    }

    @Bean("testClient")
    fun webClient(authorizedClientManager: ReactiveOAuth2AuthorizedClientManager?,
                  clientRegistrationRepository: ReactiveClientRegistrationRepository?,
                  authorizedClientRepository: ServerOAuth2AuthorizedClientRepository,
                  @Value("\${test.client.base.url}") baseUrl: String): WebClient? {

        val registrationId = "local"

        var authorizedClientManagerInternal = authorizedClientManager

        if(oAuth2ClientSSLPropertiesConfigurer.getRegistration()?.containsKey(registrationId) == true
                && oAuth2ClientSSLPropertiesConfigurer.getRegistration()!!.get(registrationId)?.sslEnabled!!) {
            val accessTokenResponseClient = WebClientReactiveClientCredentialsTokenResponseClient()

            val httpClient = HttpClient.create()
                    .tcpConfiguration { client -> client.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000) }
                    .secure { sslContextSpec: SslContextSpec -> sslContextSpec.sslContext(oAuth2ClientSSLPropertiesConfigurer.getSslContexts()?.get(registrationId)!!) }
            val httpConnector: ClientHttpConnector = ReactorClientHttpConnector(httpClient)

            accessTokenResponseClient.setWebClient(WebClient.builder().clientConnector(httpConnector).build())

            var authorizedClientProvider: ReactiveOAuth2AuthorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder.builder().clientCredentials { c: ClientCredentialsGrantBuilder -> c.accessTokenResponseClient(accessTokenResponseClient) }.build()

            authorizedClientManagerInternal = DefaultReactiveOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository)

            authorizedClientManagerInternal.setAuthorizedClientProvider(authorizedClientProvider)
        }

        val oauth = ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManagerInternal)
        oauth.setDefaultClientRegistrationId(registrationId)
        return WebClient.builder()
                .baseUrl(baseUrl)
                .filter(oauth)
                .filter(logRequest())
                .filter(logResponse())
                .build()
    }

    private fun logRequest(): ExchangeFilterFunction {
        return ExchangeFilterFunction.ofRequestProcessor { clientRequest: ClientRequest ->
            testWebClientLogger.info("Request: {} {}", clientRequest.method(), clientRequest.url())
            clientRequest.headers().forEach { name: String?, values: List<String?> -> values.forEach(Consumer { value: String? -> testWebClientLogger.info("{}={}", name, value) }) }
            Mono.just(clientRequest)
        }
    }

    private fun logResponse(): ExchangeFilterFunction {
        return ExchangeFilterFunction.ofResponseProcessor { clientResponse: ClientResponse ->
            testWebClientLogger.info("Response: {}", clientResponse.statusCode())
            Mono.just(clientResponse)
        }
    }

    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain? {
        http.oauth2Client()
        return http.build()
    }

}