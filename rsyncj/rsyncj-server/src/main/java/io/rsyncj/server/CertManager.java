package io.rsyncj.server;

import io.rsyncj.common.util.Hex;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Creates (on first start) and loads the server's self-signed TLS certificate.
 * The certificate fingerprint is what clients pin, SSH-style.
 */
public final class CertManager {

    private static final String ALIAS = "rsyncj";

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private CertManager() {
    }

    public static KeyStore loadOrCreate(Path keystoreFile, char[] password) throws Exception {
        if (Files.exists(keystoreFile)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(keystoreFile)) {
                keyStore.load(in, password);
            }
            return keyStore;
        }
        KeyStore keyStore = generate(password);
        Path parent = keystoreFile.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path temp = Files.createTempFile(parent, ".keystore-", ".tmp");
        try (OutputStream out = Files.newOutputStream(temp)) {
            keyStore.store(out, password);
        }
        try {
            Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // non-POSIX filesystem
        }
        Files.move(temp, keystoreFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        return keyStore;
    }

    private static KeyStore generate(char[] password) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();

        X500Name subject = new X500Name("CN=rsyncj, O=rsyncj, OU=secure-file-sync");
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(now.plus(3650, ChronoUnit.DAYS));
        BigInteger serial = new BigInteger(96, new SecureRandom()).abs();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement));
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        }));

        var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(ALIAS, keyPair.getPrivate(), password, new Certificate[]{certificate});
        return keyStore;
    }

    public static X509Certificate certificate(KeyStore keyStore) throws Exception {
        return (X509Certificate) keyStore.getCertificate(ALIAS);
    }

    public static String fingerprint(KeyStore keyStore) throws Exception {
        return Hex.encode(io.rsyncj.common.crypto.Scram.sha256(certificate(keyStore).getEncoded()));
    }

    public static SSLContext sslContext(KeyStore keyStore, char[] password) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, password);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
        return context;
    }
}
