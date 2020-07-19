package `in`.neuw.oauth2.util.security

import io.netty.handler.ssl.ClientAuth
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.FingerprintTrustManagerFactory
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.util.*
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory

class SSLContextHelper {

    companion object {
        @JvmStatic
        fun sslContext(keyManagerFactory: KeyManagerFactory, trustManagerFactory: TrustManagerFactory): SslContext {
            val sslContext: SslContext = SslContextBuilder.forClient()
                    .clientAuth(ClientAuth.REQUIRE)
                    // the following line is not recommended and not used either
                    //.trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .keyManager(keyManagerFactory)
                    .trustManager(trustManagerFactory)
                    .build()
            return sslContext;
        }

        /*
         * Create the Key Store.
         */
        @JvmStatic
        fun getKeyStore(keystoreContent: String, keyStorePassword: String): KeyManagerFactory {
            val keyStore = KeyStore.getInstance("JKS")
            val decoder = Base64.getMimeDecoder()
            val inputStream = ByteArrayInputStream(decoder.decode(keystoreContent))
            keyStore.load(inputStream, keyStorePassword?.toCharArray())
            val kmf = KeyManagerFactory.getInstance("SunX509")
            kmf.init(keyStore, keyStorePassword.toCharArray())
            return kmf
        }

        /*
         * Create the Trust Store.
         */
        @JvmStatic
        fun getTrustStore(truststoreContent: String, trustStorePassword: String): TrustManagerFactory {
            val trustStore = KeyStore.getInstance("JKS")
            val decoder = Base64.getMimeDecoder()
            val inputStream = ByteArrayInputStream(decoder.decode(truststoreContent))
            trustStore.load(inputStream, trustStorePassword?.toCharArray())
            val tmf = FingerprintTrustManagerFactory.getInstance(FingerprintTrustManagerFactory.getDefaultAlgorithm())
            tmf.init(trustStore)
            return tmf
        }
    }

}